//
// Created by yuki on 2020/5/17.
//

#include "file.h"

using namespace file;

file_reader::file_reader(std::string _file_name, const int &buff_size)
    : buff_s(buff_size){

  // using std::filesystem library to check file availability
  try {
    #ifdef WIN32
    std::replace(_file_name.begin(), _file_name.end(), '/', '\\');
    #else
    std::replace(_file_name.begin(), _file_name.end(), '\\', '/');
    #endif
    file_size = fs::file_size(_file_name);
  }
  catch (fs::filesystem_error &e) {
    std::cout << "Failed in reading file." << std::endl;
    // since some error occured during reading the file, we simply exit
    exit(1);
  }

  if (file_size == -1) {
    std::cout << "Failed in reading file: File not exist." << std::endl;
    // since the file not exist, we simply exit
    exit(1);
  }

  // open the file in binary read mode
  _file.open(_file_name, std::ios::in | std::ios::binary);
  // put the pointer to the begin of the file
  _file.seekg(0);

  // file opened successfully
  ok = true;
}

file_reader::~file_reader() {
  // close the file when file_reader object is recycled
  // - but only if it is open now
  if (_file.is_open()) {
    _file.close();
  }
}

void file_reader::close() {
  if(_file.is_open()){
    _file.close();
  }
}

int file_reader::read(uint8_t *buffer) {

  // check file status before reading it
  if (!(ok && _file.is_open())) {
    return 0;
  }else if (_file.eof()) {
    ok = false;
    return 0;
  }else if (file_size < buff_s) {
    _file.read((char*)buffer, buff_s);
    // below decrease the file_size in each operation so now it is
    // the size of the last piece
    return file_size;
  } else {
    _file.read((char*)buffer, buff_s);

    // decrease the file_size to calculate size of the last piece
    file_size -= buff_s;
    return buff_s;
  }
}

int file_reader::read(char *buffer) {

  // check file status before reading it
  if (!(ok && _file.is_open())) {
    return 0;
  }else if (_file.eof()) {
    ok = false;
    return 0;
  }else if (file_size < buff_s) {
    _file.read(buffer, buff_s);
    // below decrease the file_size in each operation so now it is
    // the size of the last piece
    return file_size;
  } else {
    _file.read(buffer, buff_s);

    // decrease the file_size to calculate size of the last piece
    file_size -= buff_s;
    return buff_s;
  }
}

file_writer::file_writer(std::string _file_name, const uint64_t &file_size) {

  #ifdef WIN32
  std::replace(_file_name.begin(), _file_name.end(), '/', '\\');
  #else
  std::replace(_file_name.begin(), _file_name.end(), '\\', '/');
  #endif

  // get remaining space of parent path
  fs::space_info space = fs::space(fs::path(_file_name).parent_path());

  // throw exception when no enough space.
  if (space.available < file_size) {
    std::cout << "Failed in writing file: No enough space." << std::endl;
    throw NoEnoughSpace();
  }

  // open file in binary write mode
  _file.open(_file_name, std::ios::out | std::ios::binary);
  // put the pointer to the begin of the file
  _file.seekp(0);

  // check if file is open
  if (_file.is_open()) {
    ok = true;
  }

  std::cout<< "File opened for writing." << _file_name << std::endl;
}

void file_writer::close() {
  if (_file.is_open()) {
    _file.flush();
    _file.close();
    std::cout << "File writing closed." << std::endl;
  }
}

file_writer::~file_writer() {
  close();
}

int file_writer::write(uint8_t *buffer,int &len) {

  if (!(_file.is_open())) {
    std::cout << "File not open" << std::endl;
    return 0;
  } else {
    _file.write((char*)buffer, len);
    return len;
  }
}