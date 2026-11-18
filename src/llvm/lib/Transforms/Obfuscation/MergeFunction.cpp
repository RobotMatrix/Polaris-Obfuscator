#include "llvm/Transforms/Obfuscation/MergeFunction.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instruction.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <fstream>
#include <vector>
using namespace llvm;
namespace polaris {

// ---- S4: merge-then-split -------------------------------------------------
// The merge puts several source functions into one symbol interval; the MIR
// split then cuts that interval into chunks whose boundaries belong to no
// single source function.  That is the point of S4 -- but it also means the
// *measurement* loses the ground truth, because by MIR time only
// `__merged_function` exists.  With -merge-then-split every basic block of
// every merged source function therefore starts with an inline-asm scope
// marker (`polaris_merge_scope_<idx>`, idx into -merge-scope-sidecar).
//
// The marker is a real instruction, so it travels with its block through any
// later IR pass (flattening moves blocks, it does not rewrite their bodies);
// AArch64RubbishCode erases the markers before ISel, so no byte of them
// reaches the object.  Default off: an unflagged build has no marker, no
// sidecar and byte-identical output.
static cl::opt<bool> MergeThenSplit(
    "merge-then-split", cl::Hidden, cl::init(false),
    cl::desc("Tag every source function in the merged body with a scope "
             "marker, so the MIR split can attribute chunks to it"));
static cl::opt<std::string> MergeScopeSidecar(
    "merge-scope-sidecar", cl::Hidden, cl::init(""),
    cl::desc("Append the merged-function -> source-function map to this file"));

static void emitScopeMarker(BasicBlock *BB, unsigned Idx) {
  if (!BB)
    return;
  Module *M = BB->getModule();
  FunctionType *FTy = FunctionType::get(Type::getVoidTy(M->getContext()), false);
  InlineAsm *IA = InlineAsm::get(FTy, ("polaris_merge_scope_" + Twine(Idx)).str(),
                                 "", /*hasSideEffects=*/true);
  IRBuilder<> B(BB, BB->getFirstInsertionPt());
  B.CreateCall(FTy, IA, {}, "");
}

static void appendMergeSidecar(const std::string &Merged,
                               const std::vector<MergeInfo> &Info) {
  if (MergeScopeSidecar.empty() || Info.empty())
    return;
  std::ofstream Ofs(MergeScopeSidecar, std::ios::app);
  if (!Ofs.is_open()) {
    errs() << "[merge-then-split] cannot open " << MergeScopeSidecar << "\n";
    return;
  }
  static bool HeaderWritten = false;
  if (!HeaderWritten) {
    HeaderWritten = true;
    Ofs << "polaris-merge-scope\t1\n";
  }
  for (unsigned i = 0; i < Info.size(); i++)
    Ofs << "src\t" << Merged << "\t" << i << "\t"
        << Info[i].F->getName().str() << "\t" << Info[i].SwitchVal << "\n";
}

PreservedAnalyses MergeFunction::run(Module &M, ModuleAnalysisManager &AM) {
  process(M);
  return PreservedAnalyses::none();
}
void MergeFunction::merge(Module &M, std::vector<Function *> &ToMerge) {
  // Nothing annotated, nothing to merge: do not leave an empty
  // `__merged_function` (a one-instruction function with no cases) in the
  // module, which is a symbol an analyst would otherwise see.
  if (ToMerge.empty())
    return;
  IRBuilder<> IRB(M.getContext());
  std::vector<Type *> ArgTypes;
  ClonedCodeInfo CodeInfo;
  SmallVector<ReturnInst *, 8> Returns;
  ArgTypes.push_back(IRB.getInt32Ty());
  std::vector<MergeInfo> Info;
  uint32_t Idx = 1;
  for (Function *F : ToMerge) {
    if (!F->getReturnType()->isVoidTy()) {
      return;
    }
    MergeInfo MI;
    MI.F = F;
    MI.ArgIndex = Idx;
    for (Argument &Arg : F->args()) {
      ArgTypes.push_back(Arg.getType());
      Idx++;
    }
    Info.push_back(MI);
  }
  FunctionType *FT =
      FunctionType::get(Type::getVoidTy(M.getContext()), ArgTypes, false);
  Function *MergedF = Function::Create(FT, GlobalValue::PrivateLinkage,
                                       Twine("__merged_function"), M);
  BasicBlock *SwitchBB =
      BasicBlock::Create(M.getContext(), "switchBB", MergedF);
  BasicBlock *RetBB = BasicBlock::Create(M.getContext(), "returnBB", MergedF);
  ValueToValueMapTy VMap;
  std::vector<uint32_t> SwitchMap;
  unsigned ScopeIdx = 0;
  for (MergeInfo &MI : Info) {
    VMap.clear(), Returns.clear();
    Idx = MI.ArgIndex;
    for (Argument &Arg : MI.F->args()) {
      VMap[&Arg] = MergedF->getArg(Idx++);
    }
    CloneFunctionInto(MergedF, MI.F, VMap,
                      CloneFunctionChangeType::LocalChangesOnly, Returns, "",
                      &CodeInfo, nullptr, nullptr);
    MI.NewEntryBB = (BasicBlock *)MapValue(&MI.F->getEntryBlock(), VMap);
    // S4: one marker per cloned block (not per function entry): it has to
    // survive whatever the later IR passes do to the block layout, and after
    // the split a function entry is not the only place a chunk can start.
    if (MergeThenSplit) {
      for (BasicBlock &BB : *MI.F)
        emitScopeMarker(cast_or_null<BasicBlock>(MapValue(&BB, VMap)),
                        ScopeIdx);
    }
    uint32_t SwitchVal = getUniqueNumber(SwitchMap);
    SwitchMap.push_back(SwitchVal);
    MI.SwitchVal = SwitchVal;
    ScopeIdx++;
  }
  IRB.SetInsertPoint(SwitchBB);
  SwitchInst *SW = IRB.CreateSwitch(MergedF->getArg(0), RetBB);
  for (MergeInfo &MI : Info) {
    SW->addCase(IRB.getInt32(MI.SwitchVal), MI.NewEntryBB);
  }
  IRB.SetInsertPoint(RetBB);
  IRB.CreateRetVoid();

  // Ground truth for the measurement: which source function went into which
  // switch case of the single merged symbol interval.
  if (MergeThenSplit)
    appendMergeSidecar(MergedF->getName().str(), Info);

  for (MergeInfo &MI : Info) {
    std::vector<CallInst *> RemoveList;
    for (Function &F : M) {
      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
          if (!isa<CallInst>(I)) {
            continue;
          }

          CallInst &Call = cast<CallInst>(I);
          if (Call.getCalledFunction() == MI.F) {

            std::vector<Value *> Args;
            Args.push_back(IRB.getInt32(MI.SwitchVal));
            for (size_t i = 1; i < MergedF->arg_size(); i++) {
              if (i >= MI.ArgIndex && i < MI.ArgIndex + MI.F->arg_size()) {
                Args.push_back(Call.getArgOperand(i - MI.ArgIndex));
              } else {
                Args.push_back(
                    Constant::getNullValue(MergedF->getArg(i)->getType()));
              }
            }
            IRB.SetInsertPoint(&Call);
            IRB.CreateCall(FunctionCallee(MergedF), Args);
            RemoveList.push_back(&Call);
          }
        }
      }
    }
    for (CallInst *C : RemoveList) {
      C->eraseFromParent();
    }
  }
  for (MergeInfo &MI : Info) {
    MI.F->eraseFromParent();
  }
}
void MergeFunction::process(Module &M) {
  std::vector<Function *> MergeList;
  SmallVector<ReturnInst *, 8> Returns;
  ValueToValueMapTy VMap;
  ClonedCodeInfo CodeInfo;
  IRBuilder<> IRB(M.getContext());
  // Two phases: with -merge-then-split the merge erases the functions it
  // consumes, so the list cannot be walked while that happens.
  std::vector<Function *> Targets;
  for (Function &F : M) {
    if (readAnnotate(F).find("mergefunction") != std::string::npos ||
        (readPolicyMatch(F) && policyHasPass("merge")))
      Targets.push_back(&F);
  }
  for (Function *Target : Targets) {
    Function &F = *Target;
    // S4: a void function goes into the merge as it is.  merge() clones it
    // into `__merged_function` and redirects every call site, so the source
    // function disappears -- symbol included.  Building the `_internal` clone
    // plus a thin wrapper (the path below) would keep one stub per source
    // function, i.e. keep exactly the 1:1 mapping S4 is meant to break.  The
    // trade-off is explicit: the symbol is gone, so only use this where the
    // function is not part of a published ABI.
    if (MergeThenSplit && F.getReturnType()->isVoidTy() && !F.isDeclaration()) {
      MergeList.push_back(&F);
      continue;
    }
    if (readAnnotate(F).find("mergefunction") != std::string::npos || (readPolicyMatch(F) && policyHasPass("merge"))) {
      // The stub-wrapper path: F keeps its symbol and its body is moved into
      // `<name>_internal`.  Still used for non-void functions, where the
      // caller needs a returned value; see the S4 branch above for why void
      // functions with -merge-then-split do not come through here.
      VMap.clear(), Returns.clear();
      std::vector<Type *> ArgTypes;
      Type *RetType = F.getReturnType();
      for (Argument &Arg : F.args())
        ArgTypes.push_back(Arg.getType());
      if (!RetType->isVoidTy()) {
        ArgTypes.push_back(RetType->getPointerTo());
      }

      FunctionType *FT =
          FunctionType::get(Type::getVoidTy(M.getContext()), ArgTypes, false);
      Function *NewF = Function::Create(FT, GlobalValue::PrivateLinkage,
                                        F.getName() + "_internal", M);
      Function::arg_iterator Iter = NewF->arg_begin();
      for (Argument &Arg : F.args()) {
        VMap[&Arg] = &*Iter++;
      }
      CloneFunctionInto(NewF, &F, VMap,
                        CloneFunctionChangeType::LocalChangesOnly, Returns, "",
                        &CodeInfo, nullptr, nullptr);
      if (!RetType->isVoidTy()) {
        for (ReturnInst *Ret : Returns) {
          Value *Val = Ret->getReturnValue();
          IRB.SetInsertPoint(Ret);
          IRB.CreateStore(Val, &*Iter);
          IRB.CreateRetVoid();
          Ret->eraseFromParent();
        }
      }
      while (!F.empty()) {
        BasicBlock &BB = F.front();
        BB.eraseFromParent();
      }
      BasicBlock *Entry = BasicBlock::Create(M.getContext(), "entry", &F);
      IRB.SetInsertPoint(Entry);
      // A void function has nothing to store: CreateAlloca(void) is undefined
      // in DataLayout, and void is the shape merge() accepts, so without the
      // guard the pass could not merge the functions it was built for.
      Value *V = RetType->isVoidTy() ? nullptr : IRB.CreateAlloca(RetType);
      std::vector<Value *> ArgVal;
      for (Argument &Arg : F.args())
        ArgVal.push_back((Value *)&Arg);
      if (!RetType->isVoidTy()) {
        ArgVal.push_back(V);
      }
      IRB.CreateCall(FunctionCallee(NewF), ArgVal);
      if (!RetType->isVoidTy()) {
        IRB.CreateRet(IRB.CreateLoad(RetType, V));
      } else {
        // The wrapper still needs a terminator, or the block is malformed.
        IRB.CreateRetVoid();
      }
      MergeList.push_back(NewF);
    }
  }
  merge(M, MergeList);
}
} // namespace polaris