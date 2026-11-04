#include "llvm/Transforms/Obfuscation/BogusControlFlow2.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ValueMapper.h"
#include <vector>

using namespace llvm;

namespace polaris {

BasicBlock *cloneBasicBlock(BasicBlock *BB) {
  ValueToValueMapTy VMap;
  BasicBlock *cloneBB = CloneBasicBlock(BB, VMap, "cloneBB", BB->getParent());
  BasicBlock::iterator origI = BB->begin();
  for (Instruction &I : *cloneBB) {
    for (int i = 0; i < I.getNumOperands(); i++) {
      Value *V = MapValue(I.getOperand(i), VMap);
      if (V) {
        I.setOperand(i, V);
      }
    }
    SmallVector<std::pair<unsigned, MDNode *>, 4> MDs;
    I.getAllMetadata(MDs);
    for (std::pair<unsigned, MDNode *> pair : MDs) {
      MDNode *MD = MapMetadata(pair.second, VMap);
      if (MD) {
        I.setMetadata(pair.first, MD);
      }
    }
    I.setDebugLoc(origI->getDebugLoc());
    origI++;
  }
  return cloneBB;
}

// ((x | 1) * ((x | 1) + 1)) is even for every x, including after i32 wrap.
// The load is volatile, so the predicate is not a constant for the optimizer
// or a decompiler. One private global is shared; it is never named x or y.
static GlobalVariable *opaqueState(Module *M) {
  const char *Name = ".obf.opaque";
  if (GlobalVariable *Existing = M->getGlobalVariable(Name))
    return Existing;
  LLVMContext &Ctx = M->getContext();
  return new GlobalVariable(*M, Type::getInt32Ty(Ctx), false,
                            GlobalValue::PrivateLinkage,
                            ConstantInt::get(Type::getInt32Ty(Ctx), 0), Name);
}

Value *createBogusCmp(BasicBlock *insertAfter) {
  Module *M = insertAfter->getModule();
  IRBuilder<> Builder(insertAfter);
  LoadInst *X = Builder.CreateLoad(Builder.getInt32Ty(), opaqueState(M), true);
  Value *Odd = Builder.CreateOr(X, Builder.getInt32(1));
  Value *Even = Builder.CreateAdd(Odd, Builder.getInt32(1));
  Value *Prod = Builder.CreateMul(Odd, Even);
  Value *Rem = Builder.CreateURem(Prod, Builder.getInt32(2));
  return Builder.CreateICmpEQ(Rem, Builder.getInt32(0));
}

PreservedAnalyses BogusControlFlow2::run(Function &F,
                                         FunctionAnalysisManager &AM) {

  if (readAnnotate(F).find("boguscfg") != std::string::npos || (readPolicyMatch(F) && policyHasPass("bcf"))) {
    std::vector<BasicBlock *> origBB;
    for (BasicBlock &BB : F) {
      origBB.push_back(&BB);
    }
    for (BasicBlock *BB : origBB) {
      if (isa<InvokeInst>(BB->getTerminator()) || BB->isEHPad() ||
          (getRandomNumber() % 100) <= 20) {
        continue;
      }
      BasicBlock *headBB = BB;
      BasicBlock *bodyBB =
          BB->splitBasicBlock(BB->getFirstNonPHIOrDbgOrLifetime(), "bodyBB");
      BasicBlock *tailBB =
          bodyBB->splitBasicBlock(bodyBB->getTerminator(), "endBB");
      BasicBlock *cloneBB = cloneBasicBlock(bodyBB);

      BB->getTerminator()->eraseFromParent();
      bodyBB->getTerminator()->eraseFromParent();
      cloneBB->getTerminator()->eraseFromParent();

      Value *cond1 = createBogusCmp(BB);
      Value *cond2 = createBogusCmp(bodyBB);

      BranchInst::Create(bodyBB, cloneBB, cond1, BB);
      BranchInst::Create(tailBB, cloneBB, cond2, bodyBB);
      BranchInst::Create(bodyBB, cloneBB);
    }
    return PreservedAnalyses::none();
  }
  return PreservedAnalyses::all();
}

}; // namespace polaris
