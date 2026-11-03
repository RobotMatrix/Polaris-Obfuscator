//===- DemoteRegToStack.cpp - Move a virtual register to the stack --------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/DenseMap.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
using namespace llvm;

/// DemoteRegToStack - This function takes a virtual register computed by an
/// Instruction and replaces it with a slot in the stack frame, allocated via
/// alloca.  This allows the CFG to be changed around without fear of
/// invalidating the SSA information for the value.  It returns the pointer to
/// the alloca inserted to create a stack slot for I.
AllocaInst *llvm::DemoteRegToStack(Instruction &I, bool VolatileLoads,
                                   Instruction *AllocaPoint) {
  if (I.use_empty()) {
    I.eraseFromParent();
    return nullptr;
  }

  Function *F = I.getParent()->getParent();
  const DataLayout &DL = F->getParent()->getDataLayout();

  // Create a stack slot to hold the value.
  AllocaInst *Slot;
  if (AllocaPoint) {
    Slot = new AllocaInst(I.getType(), DL.getAllocaAddrSpace(), nullptr,
                          I.getName()+".reg2mem", AllocaPoint);
  } else {
    Slot = new AllocaInst(I.getType(), DL.getAllocaAddrSpace(), nullptr,
                          I.getName() + ".reg2mem", &F->getEntryBlock().front());
  }

  // We cannot demote invoke instructions to the stack if their normal edge
  // is critical. Therefore, split the critical edge and create a basic block
  // into which the store can be inserted.
  // [FIX] Split the normal edge UNCONDITIONALLY (not only when critical).
  // Downstream CFG rewrites (e.g. obfuscation flattening) add new edges to
  // the normal destination. If the store lives in that shared block, a
  // bypassing edge reaches the store with the invoke result undefined =>
  // invalid SSA. A dedicated split block keeps the store on the invoke-only
  // edge, and since the split block is created after any caller's block
  // collection, later rewrites never add edges to it.
  if (InvokeInst *II = dyn_cast<InvokeInst>(&I)) {
    // [FIX] Dedicate a fresh block on the invoke's normal edge so the store
    // lands on the invoke-only path. Downstream CFG rewrites (e.g. obfuscation
    // flattening) add bypass edges to the original normal destination; a
    // store placed there would then execute with the invoke result undefined
    // (invalid SSA). The new block is invisible to such rewrites because it
    // is created after their block collection.
    BasicBlock *SrcBB = II->getParent();
    BasicBlock *OrigDest = II->getNormalDest();
    BasicBlock *StoreBB = BasicBlock::Create(
        SrcBB->getContext(), "invoke.demote.store", SrcBB->getParent(),
        OrigDest->getNextNode());
    II->setNormalDest(StoreBB);
    // Reconnect PHIs: the incoming edge for this invoke now goes via StoreBB.
    for (PHINode &PN : OrigDest->phis())
      PN.replaceIncomingBlockWith(SrcBB, StoreBB);
    new StoreInst(&I, Slot, StoreBB);
    BranchInst::Create(OrigDest, StoreBB);
  }

  // Change all of the users of the instruction to read from the stack slot.
  while (!I.use_empty()) {
    Instruction *U = cast<Instruction>(I.user_back());
    if (PHINode *PN = dyn_cast<PHINode>(U)) {
      // If this is a PHI node, we can't insert a load of the value before the
      // use.  Instead insert the load in the predecessor block corresponding
      // to the incoming value.
      //
      // Note that if there are multiple edges from a basic block to this PHI
      // node that we cannot have multiple loads. The problem is that the
      // resulting PHI node will have multiple values (from each load) coming in
      // from the same block, which is illegal SSA form. For this reason, we
      // keep track of and reuse loads we insert.
      DenseMap<BasicBlock*, Value*> Loads;
      for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; ++i)
        if (PN->getIncomingValue(i) == &I) {
          Value *&V = Loads[PN->getIncomingBlock(i)];
          if (!V) {
            // Insert the load into the predecessor block
            V = new LoadInst(I.getType(), Slot, I.getName() + ".reload",
                             VolatileLoads,
                             PN->getIncomingBlock(i)->getTerminator());
          }
          PN->setIncomingValue(i, V);
        }

    } else {
      // If this is a normal instruction, just insert a load.
      Value *V = new LoadInst(I.getType(), Slot, I.getName() + ".reload",
                              VolatileLoads, U);
      U->replaceUsesOfWith(&I, V);
    }
  }

  // Insert stores of the computed value into the stack slot. We have to be
  // careful if I is an invoke instruction, because we can't insert the store
  // AFTER the terminator instruction.
  BasicBlock::iterator InsertPt;
  if (!I.isTerminator()) {
    InsertPt = ++I.getIterator();
    // Don't insert before PHI nodes or landingpad instrs.
    for (; isa<PHINode>(InsertPt) || InsertPt->isEHPad(); ++InsertPt)
      if (isa<CatchSwitchInst>(InsertPt))
        break;
    if (isa<CatchSwitchInst>(InsertPt)) {
      for (BasicBlock *Handler : successors(&*InsertPt))
        new StoreInst(&I, Slot, &*Handler->getFirstInsertionPt());
      return Slot;
    }
  } else {
    InvokeInst &II = cast<InvokeInst>(I);
    InsertPt = II.getNormalDest()->getFirstInsertionPt();
  }

  new StoreInst(&I, Slot, &*InsertPt);
  return Slot;
}

/// DemotePHIToStack - This function takes a virtual register computed by a PHI
/// node and replaces it with a slot in the stack frame allocated via alloca.
/// The PHI node is deleted. It returns the pointer to the alloca inserted.
AllocaInst *llvm::DemotePHIToStack(PHINode *P, Instruction *AllocaPoint) {
  if (P->use_empty()) {
    P->eraseFromParent();
    return nullptr;
  }

  const DataLayout &DL = P->getModule()->getDataLayout();

  // Create a stack slot to hold the value.
  AllocaInst *Slot;
  if (AllocaPoint) {
    Slot = new AllocaInst(P->getType(), DL.getAllocaAddrSpace(), nullptr,
                          P->getName()+".reg2mem", AllocaPoint);
  } else {
    Function *F = P->getParent()->getParent();
    Slot = new AllocaInst(P->getType(), DL.getAllocaAddrSpace(), nullptr,
                          P->getName() + ".reg2mem",
                          &F->getEntryBlock().front());
  }

  // Iterate over each operand inserting a store in each predecessor.
  for (unsigned i = 0, e = P->getNumIncomingValues(); i < e; ++i) {
    Value *Incoming = P->getIncomingValue(i);
    BasicBlock *IncomingBB = P->getIncomingBlock(i);
    if (auto *II = dyn_cast<InvokeInst>(Incoming)) {
      // [FIX] The incoming value is the result of the invoke that terminates
      // IncomingBB. A store inserted before the invoke would read its own
      // result before definition (invalid SSA). Route the store through a
      // dedicated block on the invoke's normal edge instead.
      BasicBlock *SrcBB = II->getParent();
      BasicBlock *OrigDest = II->getNormalDest();
      BasicBlock *StoreBB = BasicBlock::Create(
          SrcBB->getContext(), "invoke.phi.store", SrcBB->getParent(),
          OrigDest->getNextNode());
      II->setNormalDest(StoreBB);
      for (PHINode &OtherPN : OrigDest->phis())
        if (&OtherPN != P)
          OtherPN.replaceIncomingBlockWith(SrcBB, StoreBB);
      new StoreInst(Incoming, Slot, StoreBB);
      BranchInst::Create(OrigDest, StoreBB);
      continue;
    }
    new StoreInst(Incoming, Slot, IncomingBB->getTerminator());
  }

  // Insert a load in place of the PHI and replace all uses.
  BasicBlock::iterator InsertPt = P->getIterator();
  // Don't insert before PHI nodes or landingpad instrs.
  for (; isa<PHINode>(InsertPt) || InsertPt->isEHPad(); ++InsertPt)
    if (isa<CatchSwitchInst>(InsertPt))
      break;
  if (isa<CatchSwitchInst>(InsertPt)) {
    // We need a separate load before each actual use of the PHI
    SmallVector<Instruction *, 4> Users;
    for (User *U : P->users()) {
      Instruction *User = cast<Instruction>(U);
      Users.push_back(User);
    }
    for (Instruction *User : Users) {
      Value *V =
          new LoadInst(P->getType(), Slot, P->getName() + ".reload", User);
      User->replaceUsesOfWith(P, V);
    }
  } else {
    Value *V =
        new LoadInst(P->getType(), Slot, P->getName() + ".reload", &*InsertPt);
    P->replaceAllUsesWith(V);
  }
  // Delete PHI.
  P->eraseFromParent();
  return Slot;
}
