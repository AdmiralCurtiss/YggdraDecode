#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "md5.h"
#include "zlib.h"

std::string rot13(std::string_view input) {
    std::string s;
    s.reserve(input.size());
    for (char c : input) {
        if (c >= 'A' && c <= 'Z') {
            if (c < 'N') {
                s.push_back(c + 13);
            } else {
                s.push_back(c - 13);
            }
        } else if (c >= 'a' && c <= 'z') {
            if (c < 'n') {
                s.push_back(c + 13);
            } else {
                s.push_back(c - 13);
            }
        } else {
            s.push_back(c);
        }
    }
    return s;
}

void decrypt(char* dst, char* src, size_t length, std::string_view filename) {
    if ((length % 4) != 0) {
        throw "length must be divisible by 4";
    }

    std::array<md5_byte_t, 16> digest;
    std::string key = rot13(filename);
    md5_state_t md5;
    md5_init(&md5);
    md5_append(&md5, (const md5_byte_t*)key.data(), key.size());
    md5_finish(&md5, digest.data());

    std::array<uint32_t, 4> xorsource;
    std::memcpy(xorsource.data(), digest.data(), 16);

    for (size_t i = 0; i < length; i += 4) {
        uint32_t tmp;
        std::memcpy(&tmp, src + i, 4);
        tmp ^= xorsource[(i / 4) % 4];
        std::memcpy(dst + i, &tmp, 4);
    }
}

std::vector<char> ReadDecrypted(FILE* f, size_t offset, size_t length, std::string_view filename) {
    _fseeki64(f, offset, SEEK_SET);

    std::vector<char> in_data;
    in_data.resize(length);
    fread(in_data.data(), 1, in_data.size(), f);

    std::vector<char> out_data;
    out_data.resize(in_data.size());

    decrypt(out_data.data(), in_data.data(), in_data.size(), filename);

    return out_data;
}

std::vector<char> Decompress(const std::vector<char>& out_data) {
    std::vector<char> decomp_data;
    uint32_t decompSize;
    std::memcpy(&decompSize, out_data.data(), 4);
    decomp_data.resize(decompSize);

    z_stream zs{};
    inflateInit(&zs);

    zs.avail_in = out_data.size() - 4;
    zs.next_in = (Bytef*)out_data.data() + 4;
    zs.avail_out = decomp_data.size();
    zs.next_out = (Bytef*)decomp_data.data();
    inflate(&zs, Z_FINISH);

    return decomp_data;
}

struct FileTableEntry {
    bool Extracted = false;
    std::string Name;

    uint32_t NameOffset; // offset into the strings section of InfoData
    uint32_t Length;     // two highest bits are flags
    uint32_t DataOffset; // offset into the data.bin
};

void Extract(FILE* f, std::string outfolder, std::vector<FileTableEntry>& fileTable, size_t idx,
             size_t data_offset) {
    if (idx >= fileTable.size()) {
        return;
    }
    auto& e = fileTable[idx];
    if (e.Extracted) {
        return;
    }
    e.Extracted = true;

    std::filesystem::create_directories(std::filesystem::path(outfolder));

    size_t size = e.Length & 0x3fff'ffff;
    bool isFolder = !!(e.Length & 0x8000'0000);
    bool isCompressed = !!(e.Length & 0x4000'0000);
    std::string outpath = outfolder + "/" + e.Name;

    if (isFolder) {
        size_t folder_offset = e.DataOffset / 12;
        for (size_t i = 0; i < size; ++i) {
            Extract(f, outpath, fileTable, folder_offset + i, data_offset);
        }
    } else {
        size_t extra_bytes = size & 3;
        size_t aligned_size = extra_bytes ? (size + 4 - extra_bytes) : size;

        auto data = ReadDecrypted(f, data_offset + e.DataOffset, aligned_size, e.Name);
        if (isCompressed) {
            extra_bytes = 0;
            data = Decompress(data);
        }
        FILE* f2 = fopen(outpath.c_str(), "wb");
        fwrite(data.data(), 1, data.size() - (extra_bytes ? (4 - extra_bytes) : 0), f2);
        fclose(f2);
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("usage: YggdraDecode data.bin\n");
        return -1;
    }

    std::string infilepath = argv[1];

    // const char* filename = "NowLoading16.webp";
    // size_t filesize = 0x34c8;
    // size_t offset = 0x4d4c;

    // const char* filename = "Card_TacSele.pck";
    // size_t filesize = 0x000402a5 * 4;
    // size_t offset = 0xa19e298;

    const char* filename = "InfoData";
    size_t infodata_filesize = 0x4d44;
    size_t infodata_offset = 0x8;
    std::array<char, 8> infodata_info_bytes;

    FILE* f = fopen(infilepath.c_str(), "rb");
    fread(infodata_info_bytes.data(), 1, 8, f);

    std::memcpy(&infodata_filesize, infodata_info_bytes.data(), 4);
    _fseeki64(f, infodata_offset, SEEK_SET);

    std::vector<char> in_data;
    in_data.resize(infodata_filesize);
    fread(in_data.data(), 1, in_data.size(), f);

    std::vector<char> out_data;
    out_data.resize(in_data.size());

    decrypt(out_data.data(), in_data.data(), in_data.size(), filename);

    std::vector<char> decomp_data = Decompress(out_data);

    std::vector<FileTableEntry> fileTable;
    {
        uint32_t lengthData;
        uint32_t lengthStrings;
        std::memcpy(&lengthData, decomp_data.data(), 4);
        std::memcpy(&lengthStrings, decomp_data.data() + 4, 4);

        size_t offsetData = 8;
        size_t offsetStrings = offsetData + lengthData;
        size_t numberOfStrings = 0;

        size_t i = offsetData;
        while (i < offsetStrings) {
            auto& e = fileTable.emplace_back();
            std::memcpy(&e.NameOffset, decomp_data.data() + i, 4);
            std::memcpy(&e.Length, decomp_data.data() + i + 4, 4);
            std::memcpy(&e.DataOffset, decomp_data.data() + i + 8, 4);

            const auto read_string = [&]() -> std::string {
                size_t j = offsetStrings + e.NameOffset;
                std::string n;
                while (j < decomp_data.size()) {
                    if (decomp_data[j] == '\0') {
                        break;
                    }
                    n.push_back(decomp_data[j]);
                    ++j;
                }
                return n;
            };
            e.Name = read_string();
            i += 12;
        }
    }

    for (size_t i = 0; i < fileTable.size(); ++i) {
        Extract(f, infilepath + ".ex", fileTable, i, infodata_offset + infodata_filesize);
    }
}
