#include <iostream>
#include <iomanip>
#include <array>
#include <vector>

using namespace std;

int main() {
    std::array<uint8_t, 5> bytes = {0x01, 0x2a, 0x00, 0xff, 0x88};
    for (auto b : bytes) {
        cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    }
    cout << endl;
    return 0;
}
