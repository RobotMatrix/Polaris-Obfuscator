#include "llvm/IR/Function.h"
#include <string>
#include <vector>
using namespace llvm;
namespace polaris {
// JSON policy file support — no-source-marking obfuscation
void setPolicyTargets(const std::vector<std::string> &passes,
                      const std::vector<std::string> &targets);
bool loadPolicyFile(const std::string &path);
bool readPolicyMatch(Function &f);
bool policyHasPass(const std::string &pass);
std::string readAnnotate(Function &f);
uint64_t getRandomNumber();
unsigned int getUniqueNumber(std::vector<unsigned int> &rand_list);
void getRandomNoRepeat(unsigned upper_bound, unsigned size,
                       std::vector<unsigned> &result);
uint64_t getInverse(uint64_t a, uint64_t m);
void demoteRegisters(Function *f);
} // namespace polaris
