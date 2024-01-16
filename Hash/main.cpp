#include <iostream>
#include <fstream>

#include <cryptopp/sha.h>
#include <cryptopp/hex.h>

int main() {
    // Открытие файла для чтения
    std::ifstream file("file.txt", std::ios::binary);
    if (!file) {
        std::cerr << "Не удалось открыть файл\n";
        return 1;
    }

    // Чтение содержимого файла в строку
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    // Инициализация объекта хэш-функции SHA256
    CryptoPP::SHA256 hash;

    // Вычисление хэша содержимого файла
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    hash.CalculateDigest(digest, reinterpret_cast<CryptoPP::byte*>(&content[0]), content.size());

    // Преобразование байтов хэша в строку
    std::string hashStr;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashStr));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    // Запись результата хэширования в файл
    std::ofstream resultFile("result", std::ios::binary);
    if (!resultFile) {
        std::cerr << "Не удалось создать файл 'result'\n";
        return 1;
    }
    resultFile << hashStr;

    std::cout << "Хэш успешно записан в файл 'result'\n";

    return 0;
}
