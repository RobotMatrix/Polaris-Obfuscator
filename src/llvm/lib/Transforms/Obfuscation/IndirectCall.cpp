#include "llvm/Transforms/Obfuscation/IndirectCall.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Transforms/Obfuscation/Utils.h"

using namespace llvm;
namespace polaris {
PreservedAnalyses IndirectCall::run(Function &F, FunctionAnalysisManager &AM) {
  if (readAnnotate(F).find("indirectcall") != std::string::npos || (readPolicyMatch(F) && policyHasPass("indcall"))) {
    process(F);
    return PreservedAnalyses::none();
  }

  return PreservedAnalyses::all();
}
void IndirectCall::process(Function &F) {
  DataLayout Data = F.getParent()->getDataLayout();
  int PtrSize =
      Data.getTypeAllocSize(Type::getInt8Ty(F.getContext())->getPointerTo());
  Type *PtrValueType = Type::getIntNTy(F.getContext(), PtrSize * 8);
  // 32-bit non-zero mask: a wider addend does not survive Mach-O relocation.
  uint64_t KeyMask = 0xffffffffULL;
  std::vector<CallBase *> CIs;
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      auto *CB = dyn_cast<CallBase>(&I);
      if (!CB || CB->isInlineAsm())
        continue;
      Function *Func = CB->getCalledFunction();
      // InvokeInst is the call form used on exception edges. External
      // declarations and intrinsics stay direct.
      if (Func && !Func->isIntrinsic() && Func->hasExactDefinition())
        CIs.push_back(CB);
    }
  }
  for (CallBase *CI : CIs) {
    Type *Ty = CI->getFunctionType()->getPointerTo();

    Constant *Func = CI->getCalledFunction();
    Constant *CValue = ConstantExpr::getPtrToInt(
        ConstantExpr::getBitCast(Func, Ty, false), PtrValueType, false);
    uint64_t Mask = (getRandomNumber() & KeyMask) | 1;
    CValue = ConstantExpr::getAdd(CValue, ConstantInt::get(PtrValueType, Mask));
    CValue = ConstantExpr::getIntToPtr(
        CValue, Type::getInt8Ty(F.getContext())->getPointerTo());

    GlobalVariable *GV = new GlobalVariable(
        *(F.getParent()), Type::getInt8Ty(F.getContext())->getPointerTo(),
        false, GlobalValue::PrivateLinkage, NULL);
    IRBuilder<> IRB(CI);
    Value *MaskValue = ConstantInt::get(PtrValueType, Mask);
    Value *CallPtr = IRB.CreateIntToPtr(
        IRB.CreateSub(IRB.CreatePtrToInt(IRB.CreateLoad(IRB.getInt8PtrTy(), GV),
                                         PtrValueType),
                      MaskValue),
        Ty);
    CI->setCalledFunction(CI->getFunctionType(), CallPtr);
    GV->setInitializer(CValue);
  }
}
} // namespace polaris