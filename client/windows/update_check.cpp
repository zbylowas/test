#include "update.hpp"
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
static std::string read(const std::filesystem::path& path) {
    std::ifstream f(path,std::ios::binary);
    if(!f) throw std::runtime_error("Missing input file");
    return {std::istreambuf_iterator<char>(f),{}};
}
int wmain(int argc,wchar_t** argv) {
    try {
        if(argc==1) {
            if(!updates::newer("0.10.0","0.9.9") || updates::newer("1.2.3","1.2.3") ||
               updates::newer("1.2.3","1.2.4")) return 1;
            try {updates::newer("1.2.03","1.0.0");return 1;}catch(const std::exception&){}
            std::cout<<"Numeric version ordering OK\n";return 0;
        }
        if(argc!=2 && argc!=4) return 2;
        auto r=updates::verify(read(argv[1]));
        if(argc==4)updates::replace_verified(r,read(argv[2]),std::filesystem::absolute(argv[3]));
        std::cout<<"Verified "<<r.version<<"\n";return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}
}
