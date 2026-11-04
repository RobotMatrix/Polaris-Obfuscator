#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/ObfuscationSeed.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h"
#include <algorithm>
#include <ctime>
#include <random>
#include <set>
#include <fstream>
using namespace llvm;
namespace polaris {

// ---- JSON policy file state ----
static std::set<std::string> g_policy_passes;
static std::set<std::string> g_policy_targets;
static bool g_policy_loaded = false;

void setPolicyTargets(const std::vector<std::string> &passes,
                      const std::vector<std::string> &targets) {
  for (auto &p : passes) g_policy_passes.insert(p);
  for (auto &t : targets) g_policy_targets.insert(t);
  g_policy_loaded = true;
}

// 轻量 JSON 提取: 从 content 中取 "key": [ "val1", "val2" ] 的值列表
static std::vector<std::string> jsonExtractArray(const std::string &content,
                                                  const std::string &key) {
  std::vector<std::string> result;
  std::string search = "\"" + key + "\"";
  size_t pos = content.find(search);
  if (pos == std::string::npos) return result;
  pos = content.find('[', pos + search.size());
  if (pos == std::string::npos) return result;
  size_t end = content.find(']', pos);
  if (end == std::string::npos) return result;
  std::string arr = content.substr(pos + 1, end - pos - 1);
  // 提取引号内字符串
  size_t q1 = 0, q2 = 0;
  while ((q1 = arr.find('"', q2)) != std::string::npos) {
    q2 = arr.find('"', q1 + 1);
    if (q2 == std::string::npos) break;
    result.push_back(arr.substr(q1 + 1, q2 - q1 - 1));
    q2 = q2 + 1;
  }
  return result;
}

// 加载 JSON 策略文件 (从 Pipeline.cpp 调用一次)
bool loadPolicyFile(const std::string &path) {
  std::ifstream ifs(path);
  if (!ifs.is_open()) {
    errs() << "[policy] cannot open: " << path << "\n";
    return false;
  }
  std::string content((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
  auto passes = jsonExtractArray(content, "passes");
  auto targets = jsonExtractArray(content, "targets");
  // 也支持 "targets_mangled" (C++ mangled names)
  auto mangled = jsonExtractArray(content, "targets_mangled");
  for (auto &m : mangled) targets.push_back(m);
  setPolicyTargets(passes, targets);
  errs() << "[policy] loaded: " << passes.size() << " passes, "
         << targets.size() << " targets\n";
  return true;
}

// 函数名匹配 (demangled / mangled 均可)
bool readPolicyMatch(Function &f) {
  if (!g_policy_loaded || g_policy_targets.empty()) return false;
  std::string name = f.getName().str();
  if (g_policy_targets.count(name)) return true;
  // demangled 匹配 (用 llvm::demangle — 简单接口)
  std::string demangled = demangle(name);
  if (!demangled.empty() && g_policy_targets.count(demangled)) return true;
  // 子串匹配 (命名空间内函数) — 加最小长度限制防误匹配
  for (auto &t : g_policy_targets) {
    if (t.size() < 8) continue;   // 太短的目标跳过子串匹配
    if (name.find(t) != std::string::npos ||
        demangled.find(t) != std::string::npos)
      return true;
  }
  return false;
}

bool policyHasPass(const std::string &pass) {
  return g_policy_passes.count(pass) != 0;
}

std::string readAnnotate(Function &f) {
  std::string annotation = "";
  GlobalVariable *glob =
      f.getParent()->getGlobalVariable("llvm.global.annotations");
  if (glob != NULL) {
    if (ConstantArray *ca = dyn_cast<ConstantArray>(glob->getInitializer())) {
      for (unsigned i = 0; i < ca->getNumOperands(); ++i) {
        if (ConstantStruct *structAn =
                dyn_cast<ConstantStruct>(ca->getOperand(i))) {
          if (structAn->getOperand(0) == &f) {
            if (GlobalVariable *annoteStr =
                    dyn_cast<GlobalVariable>(structAn->getOperand(1))) {
              if (ConstantDataSequential *data =
                      dyn_cast<ConstantDataSequential>(
                          annoteStr->getInitializer())) {
                if (data->isString()) {
                  annotation += data->getAsString().lower() + " ";
                }
              }
            }
          }
          // structAn->dump();
        }
      }
    }
  }
  return (annotation);
}
uint64_t getRandomNumber() { return llvm::nextObfRandom(); }
uint32_t getUniqueNumber(std::vector<uint32_t> &rand_list) {
  uint32_t num = getRandomNumber() & 0xffffffff;
  while (true) {
    bool state = true;
    for (auto n = rand_list.begin(); n != rand_list.end(); n++) {
      if (*n == num) {
        state = false;
        break;
      }
    }

    if (state)
      break;
    num = getRandomNumber() & 0xffffffff;
  }
  return num;
}

void getRandomNoRepeat(unsigned upper_bound, unsigned size,
                       std::vector<unsigned> &result) {
  assert(upper_bound >= size);
  std::vector<unsigned> list;
  for (unsigned i = 0; i < upper_bound; i++) {
    list.push_back(i);
  }

  std::mt19937_64 Eng(getRandomNumber());
  std::shuffle(list.begin(), list.end(), Eng);
  for (unsigned i = 0; i < size; i++) {
    result.push_back(list[i]);
  }
}
// ax = 1 (mod m)
void exgcd(uint64_t a, uint64_t b, uint64_t &d, uint64_t &x, uint64_t &y) {
  if (!b) {
    d = a, x = 1, y = 0;
  } else {
    exgcd(b, a % b, d, y, x);
    y -= x * (a / b);
  }
}
uint64_t getInverse(uint64_t a, uint64_t m) {
  assert(a != 0);
  uint64_t x, y, d;
  exgcd(a, m, d, x, y);
  return d == 1 ? (x + m) % m : 0;
}
void demoteRegisters(Function *f) {
  std::vector<PHINode *> tmpPhi;
  std::vector<Instruction *> tmpReg;
  BasicBlock *bbEntry = &*f->begin();
  for (Function::iterator i = f->begin(); i != f->end(); i++) {
    for (BasicBlock::iterator j = i->begin(); j != i->end(); j++) {
      if (isa<PHINode>(j)) {
        PHINode *phi = cast<PHINode>(j);
        tmpPhi.push_back(phi);
        continue;
      }
      if (!(isa<AllocaInst>(j) && j->getParent() == bbEntry) &&
          j->isUsedOutsideOfBlock(&*i)) {
        tmpReg.push_back(&*j);
        continue;
      }
    }
  }
  for (unsigned int i = 0; i < tmpReg.size(); i++)
    DemoteRegToStack(*tmpReg.at(i), f->begin()->getTerminator());
  for (unsigned int i = 0; i < tmpPhi.size(); i++)
    DemotePHIToStack(tmpPhi.at(i), f->begin()->getTerminator());
  // [FIX] DemotePHIToStack replaces a PHI with a single load at the PHI site.
  // If the PHI block does not dominate a use block, that load is used
  // outside its dominance region => invalid SSA. Re-run the demote loop
  // until no instruction is used outside its block (each round converts
  // such uses into per-site loads of the same stack slot, converging fast).
  for (int round = 0; round < 10; round++) {
    std::vector<Instruction *> pending;
    for (Function::iterator i = f->begin(); i != f->end(); i++) {
      for (BasicBlock::iterator j = i->begin(); j != i->end(); j++) {
        if (isa<AllocaInst>(j) && j->getParent() == bbEntry)
          continue;
        if (j->isUsedOutsideOfBlock(&*i))
          pending.push_back(&*j);
      }
    }
    if (pending.empty())
      break;
    for (Instruction *inst : pending)
      DemoteRegToStack(*inst, f->begin()->getTerminator());
  }
}
} // namespace polaris