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
  if (!F->getFunctionType()->getReturnType()->isIntegerTy(32) ||
      F->getFunctionType()->getNumParams() != 0)
    report_fatal_error("hsvm_entry must have type i32 ()");

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
  for (uint32_t i = 0; i < kRegs; ++i)
    EB.CreateStore(EB.getInt32(0),
                   EB.CreateGEP(RegsTy, Regs, {EB.getInt32(0), EB.getInt32(i)}));

  // One block per instruction, plus a fall-off-the-end block.
  std::vector<BasicBlock *> blocks;
  blocks.reserve(slots + 1);
  for (uint32_t pc = 0; pc < slots; ++pc)
    blocks.push_back(BasicBlock::Create(Ctx, "hsvm." + std::to_string(pc), F));
  BasicBlock *OutOfRange = BasicBlock::Create(Ctx, "hsvm.pc_oob", F);
  EB.CreateBr(blocks.empty() ? OutOfRange : blocks[0]);

  auto loadReg = [&](IRBuilder<> &B, uint8_t idx) {
    return B.CreateLoad(Type::getInt32Ty(Ctx),
                        B.CreateGEP(RegsTy, Regs, {B.getInt32(0), B.getInt32(idx)}),
                        "r");
  };
  auto storeReg = [&](IRBuilder<> &B, uint8_t idx, Value *v) {
    B.CreateStore(v, B.CreateGEP(RegsTy, Regs, {B.getInt32(0), B.getInt32(idx)}));
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
      if (d.dst >= kRegs)
        report_fatal_error("hsvm: register index out of range");
      storeReg(B, d.dst, B.getInt32(d.imm));
      B.CreateBr(Next);
      break;
    case Hsv_Mov:
      if (d.dst >= kRegs || d.a >= kRegs)
        report_fatal_error("hsvm: register index out of range");
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
      if (d.dst >= kRegs || d.a >= kRegs || d.b >= kRegs)
        report_fatal_error("hsvm: register index out of range");
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
    default:
      // Memory and control flow are not lowered yet: refuse loudly.
      report_fatal_error(Twine("hsvm: opcode not lowered yet: ") + opName(d.op));
    }
  }

  IRBuilder<> OB(OutOfRange);
  OB.CreateRet(OB.getInt32(0xFFFFFFFFu));
  return PreservedAnalyses::none();
}
