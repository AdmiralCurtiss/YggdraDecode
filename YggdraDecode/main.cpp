#include <algorithm>
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

bool case_insensitive_equals(char lhs, char rhs) {
    const char c0 = (lhs >= 'a' && lhs <= 'z') ? (lhs - ('a' + 'A')) : lhs;
    const char c1 = (rhs >= 'a' && rhs <= 'z') ? (rhs - ('a' + 'A')) : rhs;
    return c0 == c1;
}

bool ends_with_case_insensitive(std::string_view string, std::string_view ending) {
    if (string.size() < ending.size()) {
        return true;
    }
    for (size_t i = 0; i < ending.size(); ++i) {
        const char cs = string[string.size() - ending.size() + i];
        const char ce = ending[i];
        if (!case_insensitive_equals(cs, ce)) {
            return false;
        }
    }
    return true;
}

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

void Crypt(char* dst, char* src, size_t length, std::string_view filename) {
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

    Crypt(out_data.data(), in_data.data(), in_data.size(), filename);

    return out_data;
}

std::vector<char> Encrypt(const std::vector<char>& in_data, std::string_view filename) {
    std::vector<char> input = in_data;
    while ((input.size() % 4) != 0) {
        input.push_back(0);
    }
    std::vector<char> output;
    output.resize(input.size());

    Crypt(output.data(), input.data(), input.size(), filename);

    return output;
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

    inflateEnd(&zs);

    return decomp_data;
}

std::vector<char> Compress(const std::vector<char>& in_data) {
    std::vector<char> comp_data;
    uint32_t decompSize = static_cast<uint32_t>(in_data.size());
    if (in_data.size() != static_cast<size_t>(decompSize)) {
        throw "data too long to compress";
    }

    z_stream zs{};
    deflateInit(&zs, 9);

    auto bound = deflateBound(&zs, decompSize);
    comp_data.resize(static_cast<size_t>(bound) + 4);
    std::memcpy(comp_data.data(), &decompSize, 4);

    zs.avail_in = decompSize;
    zs.next_in = (Bytef*)in_data.data();
    zs.avail_out = bound;
    zs.next_out = (Bytef*)comp_data.data() + 4;
    deflate(&zs, Z_FINISH);
    auto avail_out = zs.avail_out;
    deflateEnd(&zs);

    comp_data.resize((static_cast<size_t>(bound) - avail_out) + 4);


    return comp_data;
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
        // printf("Extracting folder: Length: %zu, Name: %s\n", size, e.Name.c_str());
        size_t folder_offset = e.DataOffset / 12;
        for (size_t i = 0; i < size; ++i) {
            Extract(f, outpath, fileTable, folder_offset + i, data_offset);
        }
    } else {
        // printf("Extracting file: Length: %zu, Name: %s, Compressed: %s\n", size, e.Name.c_str(),
        //        isCompressed ? "yes" : "no");
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

int ExtractArchive(FILE* f, const std::string& outfilepath) {
    const char* filename = "InfoData";
    uint32_t infodata_filesize = 0;
    const size_t infodata_offset = 0x8;
    std::array<char, 8> infodata_info_bytes;

    _fseeki64(f, 0, SEEK_SET);
    fread(infodata_info_bytes.data(), 1, 8, f);

    std::memcpy(&infodata_filesize, infodata_info_bytes.data(), 4);
    _fseeki64(f, infodata_offset, SEEK_SET);

    std::vector<char> in_data;
    in_data.resize(infodata_filesize);
    fread(in_data.data(), 1, in_data.size(), f);

    std::vector<char> out_data;
    out_data.resize(in_data.size());

    Crypt(out_data.data(), in_data.data(), in_data.size(), filename);

    std::vector<char> decomp_data = Decompress(out_data);

    //{
    //    FILE* f3 = fopen((outfilepath + "_InfoData").c_str(), "wb");
    //    fwrite(decomp_data.data(), 1, decomp_data.size(), f3);
    //    fclose(f3);
    //}

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
        Extract(f, outfilepath, fileTable, i, infodata_offset + infodata_filesize);
    }

    return 0;
}

struct PackFileEntryInternal {
    std::filesystem::path Path;
    std::string Name;
    bool IsFolder = false;
    std::vector<PackFileEntryInternal> Children;
};

struct PackFileEntry {
    std::filesystem::path Path;
    uint64_t Length = 0;
    uint64_t Offset = 0;
    std::string Name;
    bool IsFolder = false;

    bool IsRead = false;
    bool IsCompressed = false;
    bool IsEncrypted = false;
    std::vector<char> Data;
};

void CollectPackFileEntriesInternal(std::vector<PackFileEntryInternal>& entries,
                                    const std::filesystem::path& p) {
    for (const auto& entry : std::filesystem::directory_iterator(p)) {
        if (entry.is_regular_file()) {
            entries.emplace_back(
                PackFileEntryInternal{entry.path(), entry.path().filename().string(), false});
        } else if (entry.is_directory()) {
            size_t index = entries.size();
            auto& d = entries.emplace_back(
                PackFileEntryInternal{entry.path(), entry.path().filename().string(), true});

            CollectPackFileEntriesInternal(d.Children, entry.path());

            std::stable_sort(d.Children.begin(), d.Children.end(),
                             [](const PackFileEntryInternal& lhs,
                                const PackFileEntryInternal& rhs) { return lhs.Name > rhs.Name; });
        }
    }
}

void FlattenPackFileEntries(std::vector<PackFileEntry>& flat,
                            const std::vector<PackFileEntryInternal>& entries) {
    size_t startIndex = flat.size();
    for (const auto& e : entries) {
        auto& f = flat.emplace_back();
        f.Path = e.Path;
        f.Name = e.Name;
        f.IsFolder = e.IsFolder;
    }
    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];
        auto& f = flat[startIndex + i];
        if (e.IsFolder) {
            f.Length = e.Children.size();
            f.Offset = flat.size();
            FlattenPackFileEntries(flat, e.Children);
        }
    }
}

std::vector<PackFileEntry> CollectPackFileEntries(const std::filesystem::path& p) {
    std::vector<PackFileEntryInternal> entries;
    CollectPackFileEntriesInternal(entries, p);
    std::vector<PackFileEntry> flat;
    FlattenPackFileEntries(flat, entries);
    return flat;
}

int PackArchive(const std::string& infilepath, const std::string& outfilepath) {
    FILE* f = fopen(outfilepath.c_str(), "wb");
    if (!f) {
        return -1;
    }

    std::vector<PackFileEntry> entries = CollectPackFileEntries(std::filesystem::path(infilepath));

    uint64_t totalLength = 0;
    for (auto& entry : entries) {
        if (!entry.IsFolder) {
            bool shouldCompress = !(ends_with_case_insensitive(entry.Name, ".pck")
                                    || ends_with_case_insensitive(entry.Name, ".webp")
                                    || ends_with_case_insensitive(entry.Name, ".webm")
                                    || ends_with_case_insensitive(entry.Name, ".png")
                                    || ends_with_case_insensitive(entry.Name, ".ogg")
                                    || ends_with_case_insensitive(entry.Name, ".opus"));

            FILE* f2 = fopen(entry.Path.string().c_str(), "rb");
            _fseeki64(f2, 0, SEEK_END);
            auto length = _ftelli64(f2);
            _fseeki64(f2, 0, SEEK_SET);
            entry.Data.resize(length);
            fread(entry.Data.data(), 1, length, f2);
            fclose(f2);

            entry.IsRead = true;
            if (shouldCompress) {
                auto compressed = Compress(entry.Data);
                if (compressed.size() < entry.Data.size()) {
                    entry.Data = std::move(compressed);
                    entry.IsCompressed = true;
                }
            }

            entry.Length = entry.Data.size();
            auto encrypted = Encrypt(entry.Data, entry.Name);
            entry.Data = std::move(encrypted);
            entry.IsEncrypted = true;

            uint64_t extraBytes = entry.Length & 3;
            uint64_t alignedLength = extraBytes ? (entry.Length + 4 - extraBytes) : entry.Length;
            entry.Offset = totalLength;
            totalLength += alignedLength;
        }
    }

    struct HeaderEntry {
        uint32_t NameOffset; // offset into the strings section of InfoData
        uint32_t Length;     // two highest bits are flags
        uint32_t DataOffset; // offset into the data.bin
    };
    std::vector<HeaderEntry> headerData;
    std::vector<char> headerStrings;
    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& entry = entries[i];

        const auto write_string = [&headerStrings](std::string_view sv) -> size_t {
            size_t pos = headerStrings.size();
            for (char c : sv) {
                headerStrings.push_back(c);
            }
            headerStrings.push_back(0);
            return pos;
        };

        size_t nameOffset = write_string(entry.Name);
        uint32_t nameOffset32 = static_cast<uint32_t>(nameOffset);
        if (nameOffset != static_cast<size_t>(nameOffset32)) {
            throw "string table too big";
        }
        uint32_t length = 0;
        uint32_t dataOffset = 0;
        if (entry.IsFolder) {
            if (entry.Length > 0x3fff'ffffu) {
                throw "too many files in folder";
            }

            length = static_cast<uint32_t>(entry.Length | 0x8000'0000u);
            uint64_t dataOffset64 = entry.Offset * 12;
            dataOffset = static_cast<uint32_t>(dataOffset64);
            if (dataOffset != static_cast<uint64_t>(dataOffset64)) {
                throw "file table too big";
            }
        } else {
            if (entry.Length > 0x3fff'ffffu) {
                throw "single file too big";
            }

            length = static_cast<uint32_t>(entry.Length);
            if (entry.IsCompressed) {
                length = length | 0x4000'0000u;
            }
            uint64_t dataOffset64 = entry.Offset;
            dataOffset = static_cast<uint32_t>(dataOffset64);
            if (dataOffset != static_cast<uint64_t>(dataOffset64)) {
                throw "combined files too big";
            }
        }

        headerData.emplace_back(HeaderEntry{nameOffset32, length, dataOffset});
    }

    std::vector<char> infodata;
    size_t infodataLength = 8 + headerData.size() * 12 + headerStrings.size();
    infodata.resize(infodataLength);
    uint32_t headerDataLength = headerData.size() * 12;
    uint32_t headerStringsLength = headerStrings.size();
    std::memcpy(infodata.data(), &headerDataLength, 4);
    std::memcpy(infodata.data() + 4, &headerStringsLength, 4);
    for (size_t i = 0; i < headerData.size(); ++i) {
        std::memcpy(infodata.data() + 8 + i * 12, &headerData[i].NameOffset, 4);
        std::memcpy(infodata.data() + 8 + i * 12 + 4, &headerData[i].Length, 4);
        std::memcpy(infodata.data() + 8 + i * 12 + 8, &headerData[i].DataOffset, 4);
    }
    std::memcpy(infodata.data() + 8 + headerData.size() * 12, headerStrings.data(),
                headerStrings.size());

    auto infodataCompressed = Compress(infodata);
    size_t infodataCompressedLength = infodataCompressed.size();
    size_t infodataExtraBytes = infodataCompressedLength & 3;
    size_t infodataAlignedLength = infodataExtraBytes
                                       ? (infodataCompressedLength + 4 - infodataExtraBytes)
                                       : infodataCompressedLength;
    infodataCompressed.resize(infodataAlignedLength);
    std::vector<char> infodataEncrypted;
    infodataEncrypted.resize(infodataCompressed.size());
    Crypt(infodataEncrypted.data(), infodataCompressed.data(), infodataCompressed.size(),
          "InfoData");


    // header
    std::array<char, 8> infodata_info_bytes{};
    uint32_t infodata_filesize = infodataCompressedLength;
    uint32_t content_filesize = totalLength;
    std::memcpy(infodata_info_bytes.data(), &infodata_filesize, 4);
    std::memcpy(infodata_info_bytes.data() + 4, &content_filesize, 4);
    fwrite(infodata_info_bytes.data(), infodata_info_bytes.size(), 1, f);

    // infodata
    fwrite(infodataEncrypted.data(), infodataEncrypted.size(), 1, f);

    // files
    for (auto& entry : entries) {
        if (!entry.IsFolder) {
            fwrite(entry.Data.data(), entry.Data.size(), 1, f);
        }
    }

    fclose(f);

    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage for unpacking: YggdraDecode file.bin\n");
        printf("Usage for packing: YggdraDecode folder\n");
        return -1;
    }

    std::string infilepath(argv[1]);
    while (infilepath.size() > 0 && (infilepath.back() == '/' || infilepath.back() == '\\')) {
        infilepath.pop_back();
    }
    FILE* f = fopen(infilepath.c_str(), "rb");
    if (f) {
        int rv = ExtractArchive(f, infilepath + ".ex");
        fclose(f);
        return rv;
    } else if (std::filesystem::is_directory(std::filesystem::path(infilepath))) {
        return PackArchive(infilepath, infilepath + "_new.bin");
    }

    return -1;
}
