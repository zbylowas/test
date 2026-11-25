#include "update.hpp"
#include "throughput.hpp"
#include "desktop_brand.hpp"
#include <wincrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include <objbase.h>
#include <winver.h>
#include <bcrypt.h>
#include <array>
#include <charconv>
#include <memory>
#include <vector>
#include <fstream>
#include <chrono>

namespace updates {
namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::array<unsigned,3> parts(std::string_view input) {
    std::array<unsigned,3> result{};
    for (size_t i=0; i<result.size(); ++i) {
        auto end=input.find('.');
        auto part=input.substr(0,end);
        require(!part.empty() && part.size()<=5 && (part.size()==1 || part.front()!='0') &&
                (end==input.npos)==(i==2), "Niepoprawny numer wersji.");
        auto [ptr,err]=std::from_chars(part.data(),part.data()+part.size(),result[i]);
        require(err==std::errc{} && ptr==part.data()+part.size(), "Niepoprawny numer wersji.");
        if(end!=input.npos) input.remove_prefix(end+1);
    }
    return result;
}

std::vector<BYTE> decode(const std::string& input) {
    DWORD count=0;
    require(!input.empty() && input.size()<8192 && CryptStringToBinaryA(input.data(),static_cast<DWORD>(input.size()),
        CRYPT_STRING_BASE64,nullptr,&count,nullptr,nullptr), "Niepoprawne kodowanie podpisu.");
    std::vector<BYTE> data(count);
    require(CryptStringToBinaryA(input.data(),static_cast<DWORD>(input.size()),CRYPT_STRING_BASE64,
        data.data(),&count,nullptr,nullptr)!=FALSE,"Niepoprawny podpis.");
    return data;
}
std::array<BYTE,32> digest(const std::string& data) {
    std::array<BYTE,32> out{}; DWORD count=static_cast<DWORD>(out.size());
    require(CryptHashCertificate2(L"SHA256",0,nullptr,reinterpret_cast<const BYTE*>(data.data()),
        static_cast<DWORD>(data.size()),out.data(),&count)!=FALSE,"Nie można sprawdzić sumy pliku.");
    return out;
}
std::string hex_digest(const std::string& data) {
    constexpr char digits[]="0123456789abcdef";
    std::string hex;
    for(auto b:digest(data)){hex+=digits[b>>4]; hex+=digits[b&15];}
    return hex;
}
}

bool newer(const std::string& offered,const std::string& installed) { return parts(offered)>parts(installed); }

Release verify(const std::string& manifest) {
    auto m=Json::parse(manifest);
    Release r{m.at("version").get<std::string>(),m.at("sha256").get<std::string>(),0};
    parts(r.version);
    require(m.at("platform")=="windows-x64" && m.at("size").is_number_unsigned() &&
            m.at("size")>0 && m.at("size")<=33554432 && r.sha256.size()==64 &&
            r.sha256.find_first_not_of("0123456789abcdef")==std::string::npos,"Niepoprawny opis wydania Windows.");
    r.size=m.at("size").get<DWORD>();
    auto der=decode(project_signer_b64);
    std::unique_ptr<const CERT_CONTEXT,decltype(&CertFreeCertificateContext)> cert(
        CertCreateCertificateContext(X509_ASN_ENCODING,der.data(),static_cast<DWORD>(der.size())),CertFreeCertificateContext);
    BCRYPT_KEY_HANDLE key{};
    require(cert && CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,&cert->pCertInfo->SubjectPublicKeyInfo,0,nullptr,&key),
            "Nie można odczytać klucza projektu.");
    std::unique_ptr<void,decltype(&BCryptDestroyKey)> guard(key,BCryptDestroyKey);
    auto signature=decode(m.at("proof").get<std::string>());
    auto hash=digest("VIP-NET Windows x64\n"+r.version+"\n"+std::to_string(r.size)+"\n"+r.sha256+"\n");
    BCRYPT_PKCS1_PADDING_INFO pad{BCRYPT_SHA256_ALGORITHM};
    require(BCryptVerifySignature(key,&pad,hash.data(),static_cast<ULONG>(hash.size()),signature.data(),
            static_cast<ULONG>(signature.size()),BCRYPT_PAD_PKCS1)==0,"Podpis opisu wydania jest nieprawidłowy.");
    return r;
}

Release check(const std::wstring& origin) {return verify(fetch_release_bytes(origin,false));}

static std::array<unsigned,3> file_version(const std::filesystem::path& path) {
    DWORD ignored{};
    DWORD size=GetFileVersionInfoSizeW(path.c_str(),&ignored);
    require(size && size<=1048576,"Nie można odczytać wersji aplikacji na dysku.");
    std::vector<BYTE> buffer(size);
    require(GetFileVersionInfoW(path.c_str(),0,size,buffer.data())!=FALSE,"Nie można sprawdzić wersji pliku.");
    VS_FIXEDFILEINFO* info{};UINT length{};
    require(VerQueryValueW(buffer.data(),L"\\",reinterpret_cast<void**>(&info),&length) &&
            length>=sizeof(*info) && info->dwSignature==VS_FFI_SIGNATURE,"Brak wersji pliku Windows.");
    return {HIWORD(info->dwFileVersionMS),LOWORD(info->dwFileVersionMS),HIWORD(info->dwFileVersionLS)};
}

void replace_verified(const Release& r,const std::string& bytes,const std::filesystem::path& target) {
    require(bytes.size()==r.size && hex_digest(bytes)==r.sha256,"Pobrany plik ma inną sumę lub rozmiar.");
    GUID guid{}; require(CoCreateGuid(&guid)==S_OK,"Nie można przygotować aktualizacji.");
    wchar_t id[40]{}; StringFromGUID2(guid,id,40);
    auto path=target.parent_path()/(std::wstring(L".vipnet-")+id+L".tmp");
    // Serialize cooperating updater instances across releases and recheck the on-disk version.
    std::unique_ptr<void,decltype(&CloseHandle)> mutex(CreateMutexW(nullptr,FALSE,L"Local\\VIPNET-Portable-Update"),CloseHandle);
    require(mutex!=nullptr,"Nie można zabezpieczyć operacji aktualizacji.");
    DWORD wait=WaitForSingleObject(mutex.get(),0);
    require(wait==WAIT_OBJECT_0 || wait==WAIT_ABANDONED,"Inna kopia programu aktualizuje plik.");
    struct Unlock {HANDLE handle; ~Unlock(){ReleaseMutex(handle);}} unlock{mutex.get()};
    require(parts(r.version)>file_version(target),"Na dysku znajduje się już ta sama lub nowsza wersja.");
    auto file=CreateFileW(path.c_str(),GENERIC_WRITE|DELETE,FILE_SHARE_READ,nullptr,CREATE_NEW,
                          FILE_ATTRIBUTE_NORMAL,nullptr);
    require(file!=INVALID_HANDLE_VALUE,"Nie można zapisać aktualizacji w folderze aplikacji.");
    bool installed=false;
    try {
        DWORD count{};
        require(WriteFile(file,bytes.data(),r.size,&count,nullptr) && count==r.size && FlushFileBuffers(file),
                "Błąd zapisu pobranego pliku.");
        // Preserve Windows' Internet-zone handling for the replacement executable.
        auto zone=path.wstring()+L":Zone.Identifier";
        auto stream=CreateFileW(zone.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
        require(stream!=INVALID_HANDLE_VALUE,"Folder nie obsługuje bezpiecznej aktualizacji Windows.");
        constexpr char mark[]="[ZoneTransfer]\r\nZoneId=3\r\n";
        bool marked=WriteFile(stream,mark,sizeof(mark)-1,&count,nullptr) && count==sizeof(mark)-1;
        CloseHandle(stream);
        require(marked,"Nie można zapisać strefy zabezpieczeń pobranego pliku.");
        auto dest=target.wstring();
        DWORD len=static_cast<DWORD>(dest.size()*sizeof(wchar_t));
        DWORD size=sizeof(FILE_RENAME_INFO)+len;
        std::vector<BYTE> buffer(size,0);
        auto info=reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
        info->Flags=FILE_RENAME_FLAG_REPLACE_IF_EXISTS|FILE_RENAME_FLAG_POSIX_SEMANTICS;
        info->FileNameLength=len;
        memcpy(info->FileName,dest.data(),len);
        require(SetFileInformationByHandle(file,FileRenameInfoEx,info,size)!=FALSE,
                "Windows nie zezwolił na wymianę pliku. Sprawdź uprawnienia do folderu aplikacji.");
        installed=true;
    } catch(...) {
        CloseHandle(file);
        if(!installed) DeleteFileW(path.c_str());
        throw;
    }
    CloseHandle(file);
}


namespace fs=std::filesystem;
using KernelHandle=std::unique_ptr<void,decltype(&CloseHandle)>;

static fs::path module_path() {
    wchar_t path[32768]{};
    auto n=GetModuleFileNameW(nullptr,path,32768);
    require(n && n<32768,"Nie można ustalić ścieżki aplikacji.");
    return path;
}

static std::string read_limited(const fs::path& path,size_t maximum) {
    auto n=fs::file_size(path);
    require(n>0 && n<=maximum,"Niepoprawny rozmiar pliku aktualizacji.");
    std::string data(static_cast<size_t>(n),'\0');
    std::ifstream f(path,std::ios::binary);
    require(bool(f.read(data.data(),static_cast<std::streamsize>(n))) && f.peek()==EOF,"Błąd odczytu pliku aktualizacji.");
    return data;
}
static void stage(const fs::path& path,const std::string& data) {
    std::ofstream out(path,std::ios::binary);
    out.write(data.data(),static_cast<std::streamsize>(data.size()));
    out.close();
    require(bool(out),"Błąd zapisu przygotowywanej aktualizacji.");
}
static fs::path temp_root() {
    PWSTR local{};
    require(SHGetKnownFolderPath(FOLDERID_LocalAppData,KF_FLAG_DEFAULT,nullptr,&local)==S_OK,"Brak katalogu profilu Windows.");
    std::unique_ptr<wchar_t,decltype(&CoTaskMemFree)> guard(local,CoTaskMemFree);
    return fs::path(local)/L"VIP-NET-Portable-Updates";
}
static void create_private_stage(const fs::path& dir) {
    HANDLE token{};
    require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)!=FALSE,"Brak informacji o koncie Windows.");
    KernelHandle token_guard(token,CloseHandle);
    DWORD length{};TOKEN_ELEVATION level{};
    require(GetTokenInformation(token,TokenElevation,&level,sizeof(level),&length) && !level.TokenIsElevated,
            "Otwórz aplikację jako zwykły użytkownik, aby ją zaktualizować.");
    GetTokenInformation(token,TokenUser,nullptr,0,&length);
    std::vector<BYTE> storage(length);
    require(length && GetTokenInformation(token,TokenUser,storage.data(),length,&length),"Brak identyfikatora konta.");
    PWSTR sid{};
    require(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(storage.data())->User.Sid,&sid)!=FALSE,"Brak identyfikatora konta.");
    std::unique_ptr<void,decltype(&LocalFree)> sid_guard(sid,LocalFree);
    auto acl=std::wstring(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;")+sid+L")";
    PSECURITY_DESCRIPTOR sd{};
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(),SDDL_REVISION_1,&sd,nullptr)!=FALSE,"Nie można zabezpieczyć katalogu.");
    std::unique_ptr<void,decltype(&LocalFree)> sd_guard(sd,LocalFree);
    SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};
    require(CreateDirectoryW(dir.c_str(),&sa)!=FALSE,"Nie można utworzyć prywatnego katalogu instalatora.");
}
static KernelHandle lock_image(const fs::path& path) {
    auto f=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    require(f!=INVALID_HANDLE_VALUE,"Windows nie zezwolił na zabezpieczenie pliku instalatora.");
    return KernelHandle(f,CloseHandle);
}
static std::wstring ready_event(const fs::path& dir) {return L"Local\\VIP-NET-Update-"+dir.filename().wstring();}

static void clear_stage(const fs::path& dir) {
    // Only our fixed staging files in an actual directory, never follow directory junctions.
    auto attrs=GetFileAttributesW(dir.c_str());
    if(attrs==INVALID_FILE_ATTRIBUTES || (attrs&FILE_ATTRIBUTE_REPARSE_POINT))return;
    for(auto name:{L"release.json",L"candidate.bin",L"runner.exe"})DeleteFileW((dir/name).c_str());
    RemoveDirectoryW(dir.c_str());
}

void cleanup() noexcept {
    try {
        auto root=temp_root();
        if(GetFileAttributesW(root.c_str()) & FILE_ATTRIBUTE_REPARSE_POINT)return;
        for(const auto& dir:fs::directory_iterator(root)){
            auto name=dir.path().filename().wstring();
            GUID guid{};
            if(name.size()!=38 || CLSIDFromString(name.c_str(),&guid)!=S_OK)continue;
            // A successful helper keeps only its running image. Failed/pending operations keep their manifest.
            if(fs::exists(dir.path()/L"runner.exe") && !fs::exists(dir.path()/L"release.json"))clear_stage(dir.path());
        }
    }catch(...){}
}

int finish_pending_update(unsigned long pid) {
    bool applying=false;
    try {
        auto self=module_path(), dir=self.parent_path();
        GUID id{};
        require(self.filename()==L"runner.exe" && dir.parent_path()==temp_root() &&
                CLSIDFromString(dir.filename().c_str(),&id)==S_OK,"Nieprawidłowy katalog aktualizacji.");
        KernelHandle parent(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid),CloseHandle);
        KernelHandle ready(OpenEventW(EVENT_MODIFY_STATE,FALSE,ready_event(dir).c_str()),CloseHandle);
        KernelHandle commit(OpenEventW(SYNCHRONIZE,FALSE,(ready_event(dir)+L"-apply").c_str()),CloseHandle);
        wchar_t target[32768]{};DWORD length=32768;
        require(parent && ready && commit && QueryFullProcessImageNameW(parent.get(),0,target,&length),"Program źródłowy jest niedostępny.");
        auto original=hex_digest(read_limited(self,33554432));
        require(hex_digest(read_limited(target,33554432))==original,"Plik na dysku został zmieniony.");
        auto release=verify(read_limited(dir/L"release.json",8192));
        auto candidate=read_limited(dir/L"candidate.bin",33554432);
        require(candidate.size()==release.size && hex_digest(candidate)==release.sha256 &&
                parts(release.version)>file_version(target),"Niepoprawny plik lub wersja aktualizacji.");
        require(SetEvent(ready.get())!=FALSE,"Nie można potwierdzić gotowości aktualizacji.");
        HANDLE decisions[]{commit.get(),parent.get()};
        if(WaitForMultipleObjects(2,decisions,FALSE,15000)!=WAIT_OBJECT_0)return 1;
        applying=true;
        require(WaitForSingleObject(parent.get(),INFINITE)==WAIT_OBJECT_0,"Nie można potwierdzić zamknięcia programu.");
        require(hex_digest(read_limited(target,33554432))==original,"Plik aplikacji został zmieniony podczas oczekiwania.");
        replace_verified(release,candidate,target);
        clear_stage(dir);
        return 0;
    }catch(const std::exception& e){
        if(!applying)return 1;
        int n=MultiByteToWideChar(CP_UTF8,0,e.what(),-1,nullptr,0);
        std::wstring why(n,L'\0');
        if(n)MultiByteToWideChar(CP_UTF8,0,e.what(),-1,why.data(),n);
        MessageBoxW(nullptr,why.c_str(),L"Aktualizacja nie została zastosowana",MB_OK|MB_ICONERROR);
        return 1;
    }
}

void install(const Release& offered,const std::wstring& origin) {
    auto manifest=fetch_release_bytes(origin,false);
    auto release=verify(manifest);
    require(release.version==offered.version && release.sha256==offered.sha256,"Wydanie zmieniło się. Sprawdź aktualizacje ponownie.");
    auto candidate=fetch_release_bytes(origin,true);
    require(candidate.size()==release.size && hex_digest(candidate)==release.sha256,"Błąd integralności pobranego pliku.");
    GUID guid{};wchar_t id[40]{};
    require(CoCreateGuid(&guid)==S_OK && StringFromGUID2(guid,id,40),"Nie można przygotować aktualizacji.");
    auto root=temp_root(),dir=root/id;
    fs::create_directories(root);
    require(!(GetFileAttributesW(root.c_str())&FILE_ATTRIBUTE_REPARSE_POINT),
            "Nie można utworzyć katalogu aktualizacji.");
    create_private_stage(dir);
    try{
        // Make the manifest first so another instance's cleanup skips this operation.
        stage(dir/L"release.json",manifest);
        stage(dir/L"candidate.bin",candidate);
        auto helper=dir/L"runner.exe";
        auto original=module_path();
        auto source_lock=lock_image(original);
        require(CopyFileW(original.c_str(),helper.c_str(),TRUE)!=FALSE,"Nie można przygotować programu instalującego.");
        auto helper_lock=lock_image(helper);
        require(hex_digest(read_limited(original,33554432))==hex_digest(read_limited(helper,33554432)),
                "Kopia instalatora nie odpowiada uruchomionej aplikacji.");
        KernelHandle commit(CreateEventW(nullptr,TRUE,FALSE,(ready_event(dir)+L"-apply").c_str()),CloseHandle);
        require(commit && GetLastError()!=ERROR_ALREADY_EXISTS,"Nie można zabezpieczyć zatwierdzenia instalacji.");
        KernelHandle ready(CreateEventW(nullptr,TRUE,FALSE,ready_event(dir).c_str()),CloseHandle);
        require(ready && GetLastError()!=ERROR_ALREADY_EXISTS,"Nie można potwierdzić stanu instalatora.");
        auto cmd=L"\""+helper.wstring()+L"\" --finish-update "+std::to_wstring(GetCurrentProcessId());
        STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
        require(CreateProcessW(helper.c_str(),cmd.data(),nullptr,nullptr,FALSE,0,nullptr,dir.c_str(),&si,&pi)!=FALSE,
                "Windows nie uruchomił instalatora.");
        CloseHandle(pi.hThread);
        KernelHandle child(pi.hProcess,CloseHandle);
        HANDLE handles[]{ready.get(),child.get()};
        require(WaitForMultipleObjects(2,handles,FALSE,15000)==WAIT_OBJECT_0,"Instalator nie potwierdził gotowości.");
        require(SetEvent(commit.get())!=FALSE,"Nie można zatwierdzić instalacji.");
    }catch(...){clear_stage(dir);throw;}
}
}
