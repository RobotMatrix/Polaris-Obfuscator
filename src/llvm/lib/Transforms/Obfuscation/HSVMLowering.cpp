//===- HSVMLowering.cpp - HSV bytecode to native IR (stage 5, V-08) --------===//
//
// Contract:
//   @hsvm.bytecode : constant array of i8, 8 bytes per instruction
//   @hsvm_entry    : declared "i32 ()" - its body is replaced by the lowered
//                    program, which returns the final value of r0
//
// This slice lowers the register-class opcodes (Nop, Movi, Mov, Add..Shr) and
// the stop instruction. Memory and control flow arrive in the next slice; until
// then the pass refuses such bytecode with a fatal error, because a silent
// approximation would be a miscompile that looks like success.
//
// Opcode values come from HSVMOpcodes.def, the single source of truth shared
// with research/hsvm/include/hsvm/isa.h.
//===-===----------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/HSVMLowering.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace {

// Values mirror HSVMOpcodes.def; the include below makes that literal.
enum HsvOp : uint8_t {
#define HSV_OPCODE(name, value) Hsv_##name = value,
#include "llvm/Transforms/Obfuscation/HSVMOpcodes.def"
#undef HSV_OPCODE
};

constexpr uint32_t kRegs = 16;
constexpr uint32_t kInstrBytes = 8;
constexpr uint32_t kMemBytes = 4096;

struct Decoded {
  uint8_t op = 0;
  uint8_t dst = 0;
  uint8_t a = 0;
  uint8_t b = 0;
  uint32_t imm = 0;
};

bool readByte(llvm::Constant *bc, uint32_t off, uint8_t *out) {
  llvm::Constant *el = bc->getAggregateElement(off);
  auto *ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(el);
  if (!ci)
    return false;
  *out = static_cast<uint8_t>(ci->getZExtValue() & 0xFFu);
  return true;
}

bool decodeAt(llvm::Constant *bc, uint32_t pc, Decoded *d) {
  const uint32_t base = pc * kInstrBytes;
  uint8_t bytes[kInstrBytes];
  for (uint32_t i = 0; i < kInstrBytes; ++i)
    if (!readByte(bc, base + i, &bytes[i]))
      return false;
  d->op = bytes[0];
  d->dst = bytes[1];
  d->a = bytes[2];
  d->b = bytes[3];
  d->imm = static_cast<uint32_t>(bytes[4]) | (static_cast<uint32_t>(bytes[5]) << 8) |
           (static_cast<uint32_t>(bytes[6]) << 16) |
           (static_cast<uint32_t>(bytes[7]) << 24);
  return true;
}

const char *opName(uint8_t op) {
  switch (op) {
#define HSV_OPCODE(name, value)                                                \
  case Hsv_##name:                                                             \
    return #name;
#include "llvm/Transforms/Obfuscation/HSVMOpcodes.def"
#undef HSV_OPCODE
  default:
    return "?";
  }
}

} // namespace

using namespace llvm;
using namespace polaris;

PreservedAnalyses HSVMLowering::run(Module &M, ModuleAnalysisManager &AM) {
  (void)AM;
  // The C spelling is hsvm_bytecode; the dotted form is kept for IR produced by
  // other front ends. Either name is accepted, nothing else.
  GlobalVariable *BC = M.getNamedGlobal("hsvm_bytecode");
  if (!BC)
    BC = M.getNamedGlobal("hsvm.bytecode");
  Function *F = M.getFunction("hsvm_entry");
  // Both are required; without them the pass is simply not applicable.
  if (!BC || !F || !BC->hasInitializer())
    return PreservedAnalyses::all();
  // i32 () takes its initial register fill from @hsvm_init; i32 (i32) takes it
  // from the argument, which is what lets a caller feed runtime input and stops
  // the optimiser from folding the whole program away.
  if (!F->getFunctionType()->getReturnType()->isIntegerTy(32))
    report_fatal_error("hsvm_entry must return i32");
  const unsigned numParams = F->getFunctionType()->getNumParams();
  if (numParams > 1)
    report_fatal_error("hsvm_entry must take zero or one i32 argument");
  if (numParams == 1 &&
      !F->getFunctionType()->getParamType(0)->isIntegerTy(32))
    report_fatal_error("hsvm_entry argument must be i32");

  Constant *Init = BC->getInitializer();
  auto *ArrTy = dyn_cast<ArrayType>(Init->getType());
  if (!ArrTy || !ArrTy->getElementType()->isIntegerTy(8))
    report_fatal_error("hsvm.bytecode must be a constant array of i8");
  const uint64_t totalBytes = ArrTy->getNumElements();
  if (totalBytes % kInstrBytes != 0)
    report_fatal_error("hsvm.bytecode length must be a multiple of 8");
  const uint32_t slots = static_cast<uint32_t>(totalBytes / kInstrBytes);

  F->deleteBody();
  LLVMContext &Ctx = M.getContext();
  ArrayType *RegsTy = ArrayType::get(Type::getInt32Ty(Ctx), kRegs);
  BasicBlock *Entry = BasicBlock::Create(Ctx, "hsvm.entry", F);
  IRBuilder<> EB(Entry);
  AllocaInst *Regs = EB.CreateAlloca(RegsTy, nullptr, "hsvm.regs");
  // Optional initial register value: @hsvm_init (i32 constant). Without it the
  // file starts zeroed, which is what the interpreter does for a zeroed fill.
  uint32_t initRegs = 0;
  if (GlobalVariable *GI = M.getNamedGlobal("hsvm_init"))
    if (auto *CI = dyn_cast_or_null<ConstantInt>(GI->getInitializer()))
      initRegs = static_cast<uint32_t>(CI->getZExtValue());
  Value *InitVal = EB.getInt32(initRegs);
  if (numParams == 1)
    InitVal = F->getArg(0);
  for (uint32_t i = 0; i < kRegs; ++i)
    EB.CreateStore(InitVal,
                   EB.CreateGEP(RegsTy, Regs, {EB.getInt32(0), EB.getInt32(i)}));
  // The interpreter's memory starts zeroed; an alloca does not, so fill it.
  ArrayType *MemTy = ArrayType::get(Type::getInt8Ty(Ctx), kMemBytes);
  AllocaInst *Mem = EB.CreateAlloca(MemTy, nullptr, "hsvm.mem");
  EB.CreateMemSet(Mem, EB.getInt8(0), kMemBytes, MaybeAlign(4));

  // One block per instruction, plus a fall-off-the-end block.
  std::vector<BasicBlock *> blocks;
  blocks.reserve(slots + 1);
  for (uint32_t pc = 0; pc < slots; ++pc)
    blocks.push_back(BasicBlock::Create(Ctx, "hsvm." + std::to_string(pc), F));
  BasicBlock *OutOfRange = BasicBlock::Create(Ctx, "hsvm.pc_oob", F);
  BasicBlock *FaultBlk = BasicBlock::Create(Ctx, "hsvm.fault", F);
  EB.CreateBr(blocks.empty() ? OutOfRange : blocks[0]);

  auto loadReg = [&](IRBuilder<> &B, uint8_t idx) {
    return B.CreateLoad(Type::getInt32Ty(Ctx),
                        B.CreateGEP(RegsTy, Regs, {B.getInt32(0), B.getInt32(idx)}),
                        "r");
  };
  auto storeReg = [&](IRBuilder<> &B, uint8_t idx, Value *v) {
    B.CreateStore(v, B.CreateGEP(RegsTy, Regs, {B.getInt32(0), B.getInt32(idx)}));
  };

  auto memByte = [&](IRBuilder<> &B, Value *addr) {
    return B.CreateGEP(MemTy, Mem, {B.getInt32(0), addr});
  };
  // Byte address must be 4-aligned and leave room for a word; otherwise the
  // interpreter faults and so must we.
  auto checkAddr = [&](IRBuilder<> &B, Value *addr, BasicBlock *Ok,
                       BasicBlock *Bad) {
    Value *hi = B.CreateICmpUGT(addr, B.getInt32(kMemBytes - 4));
    Value *mis = B.CreateICmpNE(B.CreateAnd(addr, B.getInt32(3)), B.getInt32(0));
    B.CreateCondBr(B.CreateOr(hi, mis), Bad, Ok);
  };

  for (uint32_t pc = 0; pc < slots; ++pc) {
    Decoded d;
    if (!decodeAt(Init, pc, &d)) {
      F->erase(F->begin(), F->end());
      report_fatal_error("hsvm.bytecode is not a readable constant array");
    }
    IRBuilder<> B(blocks[pc]);
    BasicBlock *Next = (pc + 1 < slots) ? blocks[pc + 1] : OutOfRange;
    switch (d.op) {
    case Hsv_Nop:
      B.CreateBr(Next);
      break;
    case Hsv_Movi:
      if (d.dst >= kRegs) {
        B.CreateBr(FaultBlk);
        break;
      }
      storeReg(B, d.dst, B.getInt32(d.imm));
      B.CreateBr(Next);
      break;
    case Hsv_Mov:
      if (d.dst >= kRegs || d.a >= kRegs) {
        B.CreateBr(FaultBlk);
        break;
      }
      storeReg(B, d.dst, loadReg(B, d.a));
      B.CreateBr(Next);
      break;
    case Hsv_Add:
    case Hsv_Sub:
    case Hsv_Xor:
    case Hsv_And:
    case Hsv_Or:
    case Hsv_Mul:
    case Hsv_Shl:
    case Hsv_Shr: {
      if (d.dst >= kRegs || d.a >= kRegs || d.b >= kRegs) {
        B.CreateBr(FaultBlk);
        break;
      }
      Value *x = loadReg(B, d.a);
      Value *y = loadReg(B, d.b);
      Value *r = nullptr;
      switch (d.op) {
      case Hsv_Add: r = B.CreateAdd(x, y); break;
      case Hsv_Sub: r = B.CreateSub(x, y); break;
      case Hsv_Xor: r = B.CreateXor(x, y); break;
      case Hsv_And: r = B.CreateAnd(x, y); break;
      case Hsv_Or: r = B.CreateOr(x, y); break;
      case Hsv_Mul: r = B.CreateMul(x, y); break;
      case Hsv_Shl:
        r = B.CreateShl(x, B.CreateAnd(y, B.getInt32(31)));
        break;
      case Hsv_Shr:
        r = B.CreateLShr(x, B.CreateAnd(y, B.getInt32(31)));
        break;
      default: break;
      }
      storeReg(B, d.dst, r);
      B.CreateBr(Next);
      break;
    }
    case Hsv_Halt:
      B.CreateRet(loadReg(B, 0));
      break;
    case Hsv_Ld: {
      if (d.dst >= kRegs || d.a >= kRegs) {
        B.CreateBr(FaultBlk);
        break;
      }
      Value *addr = B.CreateAdd(loadReg(B, d.a), B.getInt32(d.imm));
      BasicBlock *Cont = BasicBlock::Create(Ctx, "hsvm.ld", F);
      checkAddr(B, addr, Cont, FaultBlk);
      IRBuilder<> CB(Cont);
      Value *v = CB.getInt32(0);
      for (uint32_t k = 0; k < 4; ++k) {
        Value *bp = CB.CreateAdd(addr, CB.getInt32(k));
        Value *byte = CB.CreateZExt(CB.CreateLoad(Type::getInt8Ty(Ctx), memByte(CB, bp)),
                                    Type::getInt32Ty(Ctx));
        if (k != 0)
          byte = CB.CreateShl(byte, 8 * k);
        v = CB.CreateOr(v, byte);
      }
      storeReg(CB, d.dst, v);
      CB.CreateBr(Next);
      break;
    }
    case Hsv_Tld: {
      if (d.dst >= kRegs || d.a >= kRegs) {
        B.CreateBr(FaultBlk);
        break;
      }
      Module &Mod = *F->getParent();
      GlobalVariable *TP = Mod.getGlobalVariable("hsvm_table");
      GlobalVariable *TL = Mod.getGlobalVariable("hsvm_table_len");
      if (!TP || !TL)
        report_fatal_error(
            "hsvm: Tld needs @hsvm_table (pointer) and @hsvm_table_len (i64)");
      Value *addr32 = B.CreateAdd(loadReg(B, d.a), B.getInt32(d.imm));
      Value *tbl = B.CreateLoad(PointerType::get(Ctx, 0), TP);
      Value *len = B.CreateLoad(Type::getInt64Ty(Ctx), TL);
      Value *addr = B.CreateZExt(addr32, Type::getInt64Ty(Ctx));
      Value *fits = B.CreateICmpULE(B.CreateAdd(addr, B.getInt64(4)), len);
      Value *aligned = B.CreateICmpEQ(B.CreateAnd(addr32, B.getInt32(3)),
                                      B.getInt32(0));
      Value *nonnull = B.CreateICmpNE(tbl, ConstantPointerNull::get(
                                               PointerType::get(Ctx, 0)));
      BasicBlock *Cont = BasicBlock::Create(Ctx, "hsvm.tld", F);
      Value *ok = B.CreateAnd(B.CreateAnd(fits, aligned), nonnull);
      B.CreateCondBr(ok, Cont, FaultBlk);
      IRBuilder<> CB(Cont);
      Value *p = CB.CreateAdd(tbl, addr);
      Value *v = CB.CreateLoad(Type::getInt32Ty(Ctx), p);
      storeReg(CB, d.dst, v);
      CB.CreateBr(Next);
      break;
    }
    case Hsv_St: {
      if (d.a >= kRegs || d.b >= kRegs) {
        B.CreateBr(FaultBlk);
        break;
      }
      Value *addr = B.CreateAdd(loadReg(B, d.a), B.getInt32(d.imm));
      Value *val = loadReg(B, d.b);
      BasicBlock *Cont = BasicBlock::Create(Ctx, "hsvm.st", F);
      checkAddr(B, addr, Cont, FaultBlk);
      IRBuilder<> CB(Cont);
      for (uint32_t k = 0; k < 4; ++k) {
        Value *shifted = (k == 0) ? val : CB.CreateLShr(val, 8 * k);
        Value *byte = CB.CreateTrunc(shifted, Type::getInt8Ty(Ctx));
        Value *bp = CB.CreateAdd(addr, CB.getInt32(k));
        CB.CreateStore(byte, memByte(CB, bp));
      }
      CB.CreateBr(Next);
      break;
    }
    case Hsv_Jmp: {
      const int64_t target = static_cast<int64_t>(pc) + static_cast<int32_t>(d.imm);
      BasicBlock *T = (target < 0 || target >= static_cast<int64_t>(slots))
                          ? OutOfRange
                          : blocks[static_cast<size_t>(target)];
      B.CreateBr(T);
      break;
    }
    case Hsv_Brz: {
      if (d.a >= kRegs) {
        B.CreateBr(FaultBlk);
        break;
      }
      const int64_t target = static_cast<int64_t>(pc) + static_cast<int32_t>(d.imm);
      BasicBlock *T = (target < 0 || target >= static_cast<int64_t>(slots))
                          ? OutOfRange
                          : blocks[static_cast<size_t>(target)];
      Value *z = B.CreateICmpEQ(loadReg(B, d.a), B.getInt32(0));
      B.CreateCondBr(z, T, Next);
      break;
    }
    default:
      // An opcode outside the ISA: refuse loudly rather than miscompile.
      report_fatal_error(Twine("hsvm: unknown opcode: ") + opName(d.op));
    }
  }

  IRBuilder<> OB(OutOfRange);
  OB.CreateRet(OB.getInt32(0xFFFFFFFFu));
  // Distinct sentinels so a caller can tell the two abnormal paths apart.
  IRBuilder<> FB(FaultBlk);
  FB.CreateRet(FB.getInt32(0xFFFFFFFEu));
  return PreservedAnalyses::none();
}
