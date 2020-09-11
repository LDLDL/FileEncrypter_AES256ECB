#include <gtk/gtk.h>
#include <memory>

#include <cstring>
#include <chrono>


#include "aes256.h"
#include "file.h"
#include "pbkdf2.h"

class NotOurFile : public std::runtime_error{
 public:
  NotOurFile() : std::runtime_error("This file is not our encrypted file."){
  }
};

class WrongPassword : public std::runtime_error{
 public:
  WrongPassword() : std::runtime_error("Wrong password."){
  }
};

 class FileBroken : public std::runtime_error{
  public:
   FileBroken() : std::runtime_error("File Broken."){
   }
 };

const uint8_t HEADER[16] {
    0x59, 0x55, 0x4b, 0x49, //YUKI
    0x4d, 0x55, 0x47, 0x49, 0x59, 0x55, //MUGIYU
    0x4c, 0x44, 0x4c, 0x44, 0x4c, 0x44 //LDLDLD
};


/// \class FileEncrypter
/// \brief class to encrypt or decrypt a file
/// \datamember std::string pwd
///             password
/// \datamember std::read_file_path
///             read file path
/// \datamember std::write_file_path
///             write file path
/// \datamember ase::AES256ECB e
///             aes256ecb encrypter and decrypter
/// \datamember std::unique_ptr<file::file_reader> fr
///             file reader pointer
/// \datamember std::unique_ptr<file::file_writer> fw
///             file writer pointer
/// \datamember uint8_t *buffer
///             buffer pointer
/// \datamember int buff_size = 16
///             buffer size
/// \datamember uint64_t read_file_size
///             read file size
/// \datamember uint64_t write_file_size
///             write file size
class FileEncrypter{
 private:
  std::string pwd;
  std::string read_file_path;
  std::string write_file_path;
  aes::AES256ECB e;
  sha::sha256_stream sha;
  std::unique_ptr<file::file_reader> fr;
  std::unique_ptr<file::file_writer> fw;
  uint8_t *buffer;
  uint8_t *sha_buffer;
  int buff_size = 16;
  int sha_buff_size = 64;
  int SHA256_RESULT_SIZE = 32;
  uint64_t read_file_size;
  uint64_t write_file_size;
 public:
  /// \brief constructor
  /// \param _pwd password
  /// \param _read_file_path read file path
  /// \param _write_file_path write file path
  FileEncrypter(
      std::string &_read_file_path,
      std::string &_write_file_path,
      std::string &_pwd):
      pwd(_pwd),
      read_file_path(_read_file_path),
      write_file_path(_write_file_path),
      e(pwd),
      sha(){
    //create buffer array
    buffer = new uint8_t[buff_size];
    sha_buffer = new uint8_t[sha_buff_size];
  }

  /// \brief destructor
  /// \note close the file and delete buffer space
  ~FileEncrypter(){
    fw = nullptr;
    fr = nullptr;
    delete [] buffer;
    buffer = nullptr;
    delete [] sha_buffer;
    sha_buffer = nullptr;
  }

  /// \brief do encrypt
  void encrypt(){
    //open file
    fr = std::make_unique<file::file_reader>(read_file_path, buff_size);
    read_file_size = fr->get_size();
    write_file_size = read_file_size + 80;
    fw = std::make_unique<file::file_writer>(write_file_path, write_file_size);

    //write header and pbkdf2 stored key header
    memcpy(buffer, HEADER, 16);
    fw->write(buffer, buff_size);
    auto _k = sha::sha256_8(pwd);
    auto _pb = pbkdf2::pbkdf2_8_32_sha256(_k, 32, 4096);
    fw->write(_pb, SHA256_RESULT_SIZE);
    delete [] _k;
    delete [] _pb;

    //write file hash to head
    auto _h = calculate_sha256(read_file_path);
    fw->write(_h, SHA256_RESULT_SIZE);
    delete [] _h;

    //read size
    int _rs;
    //read 16char then encrypt then write.
    while(true){
      _rs = fr->read(buffer);
      if (_rs < buff_size)
        break;
      e.encrypt(buffer);
      fw->write(buffer, buff_size);
    }

    if(_rs){
      //_rs != 0
      //fill the blank space with a number how many chars will be filled
      int fill_num = buff_size - _rs;
      memset(buffer + _rs, fill_num, fill_num);
    }else{
      //_rs == 0
      //fill 16char of 16 then encrypt then write.
      memset(buffer, 16, buff_size);
    }

    e.encrypt(buffer);
    fw->write(buffer, buff_size);

    //close file
    fr = nullptr;
    fw = nullptr;
  }

  /// \brief do decrypt
  void decrypt(){
    //open file
    fr = std::make_unique<file::file_reader>(read_file_path, buff_size);

    //clear buffer
    memset(buffer, 0, buff_size);

    //read header and check
    fr->read(buffer);
    for(int i = 0; i < buff_size; ++i){
      if(buffer[i] != HEADER[i]){
        throw NotOurFile();
      }
    }

    //read pbkdf2 stored key header and check
    auto _k = sha::sha256_8(pwd);
    auto _pb = pbkdf2::pbkdf2_8_32_sha256(_k, 32, 4096);
    fr->read(buffer);
    for(int i = 0; i < buff_size; ++i){
      if(buffer[i] != _pb[i]){
        throw WrongPassword();
      }
    }
    fr->read(buffer);
    for(int i = 0; i < buff_size; ++i){
      if(buffer[i] != _pb[i+16]){
        throw WrongPassword();
      }
    }
    delete [] _k;
    delete [] _pb;

    //read file hash
    auto _sha_value = new uint8_t[32];
    fr->read(_sha_value);
    fr->read(_sha_value + 16);

    read_file_size = fr->get_size();
    write_file_size = read_file_size;
    fw = std::make_unique<file::file_writer>(write_file_path, write_file_size);

    //read and decrypt
    while(fr->get_size() > 16){
      fr->read(buffer);
      e.decrypt(buffer);
      fw->write(buffer, buff_size);
    }

    //remove filling
    fr->read(buffer);
    e.decrypt(buffer);
    if(buffer[15] < 16) {
      int fn = buff_size - buffer[15];
      fw->write(buffer, fn);
    }

    //close file
    fw = nullptr;
    fr = nullptr;

    auto _s = calculate_sha256(write_file_path);
    for(int i = 0; i < SHA256_RESULT_SIZE; ++i){
      if(_sha_value[i] != _s[i]){
        throw FileBroken();
      }
    }
    delete [] _s;
    delete [] _sha_value;
  }

 uint8_t *calculate_sha256(std::string &file_path){
    //open file
    auto _fr = std::make_unique<file::file_reader>(file_path, sha_buff_size);
    read_file_size = _fr->get_size();

    //read size
    int _rs;

    while(true){
      _rs = _fr->read(sha_buffer);
      if (_rs < sha_buff_size)
        break;
      sha.stream_add(sha_buffer, _rs);
    }

    sha.stream_add(sha_buffer, _rs);

    _fr->close();
    _fr = nullptr;

    return sha.get_8_result();

//    for (int i = 0; i < 32; ++i){
//      std::cout << std::hex << std::setw(2) << std::setfill('0') <<(short int)r[i];
//    }
  }
};

struct gp{
  GtkWidget *window;
  GtkWidget *file_entry;
  GtkWidget *pwd_entry;
  GtkWidget *message_label;
  GtkWidget *select_button;
  GtkWidget *encrypt_button;
  GtkWidget *decrypt_button;
  GtkWidget *exit_button;
}p;

void disable_button(gp *_p){
  gtk_widget_set_sensitive(_p->exit_button, FALSE);
  gtk_widget_set_sensitive(_p->encrypt_button, FALSE);
  gtk_widget_set_sensitive(_p->decrypt_button, FALSE);
  gtk_widget_set_sensitive(_p->select_button, FALSE);
}

void enable_button(gp *_p){
  gtk_widget_set_sensitive(_p->exit_button, TRUE);
  gtk_widget_set_sensitive(_p->encrypt_button, TRUE);
  gtk_widget_set_sensitive(_p->decrypt_button, TRUE);
  gtk_widget_set_sensitive(_p->select_button, TRUE);
}

/// \brief file_button's callback function, select file
void select_file(GtkWidget *widget, gpointer *data) {
  GtkFileChooserNative *file_chooser;
  GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
  gint res;
  gp *_p = (gp *) data;
  GtkEntry *entry = (GtkEntry *) _p->file_entry;

  file_chooser = gtk_file_chooser_native_new("Open File",
                                             GTK_WINDOW( _p->window), action, "Open", "Cancel"
  );
  res = gtk_native_dialog_run(GTK_NATIVE_DIALOG(file_chooser));
  if (res == GTK_RESPONSE_ACCEPT) {
    char *filename;
    GtkFileChooser *chooser = GTK_FILE_CHOOSER(file_chooser);
    filename = gtk_file_chooser_get_filename(chooser);
    gtk_entry_set_text(entry, filename);
  }

}

/// \brief encrypt button's call back function
void encrypt_func(GtkWidget *widget, gpointer *data){

  //time start
  std::chrono::steady_clock::time_point  now = std::chrono::steady_clock::now();

  gp *_p = (gp *) data;
  disable_button(_p);

  const char *_file_path = gtk_entry_get_text((GtkEntry *)_p->file_entry);
  const char *_pwd = gtk_entry_get_text((GtkEntry *)_p->pwd_entry);

  std::string input_file_path(_file_path);
  std::string pwd(_pwd);

  if(input_file_path.empty() or pwd.empty()){
    gtk_label_set_text((GtkLabel *) _p->message_label, "\nFile path or password must not be empty.\n");
    enable_button(_p);
    return;
  }

  std::string output_file_path = input_file_path;
  output_file_path.append(".lld");

  if(std::filesystem::exists(output_file_path)){
    gtk_label_set_text((GtkLabel *) _p->message_label, "\nEncrypted file already exists. Stop encrypt.\n");
    enable_button(_p);
    return;
  }

  gtk_label_set_text((GtkLabel *) _p->message_label, "\nEncrypting, do not close the window.\n");

  std::unique_ptr<FileEncrypter> _f(new FileEncrypter(input_file_path, output_file_path, pwd));

  try{
    _f->encrypt();
  } catch (file::NoEnoughSpace &e) {
    gtk_label_set_text((GtkLabel *) _p->message_label, "\nNo enough space to store encrypted file.\n");
    _f = nullptr;
    enable_button(_p);
    return;
  }

  _f = nullptr;

  // get time info
  auto t2 = std::chrono::steady_clock::now();
  std::chrono::duration<double> time_span =
      std::chrono::duration_cast<std::chrono::duration<double>>(t2 - now);

  std::string info("\nEncrypt finished using ");
  info.append(std::to_string(time_span.count()));
  info.append(" seconds.\n");

  gtk_label_set_text((GtkLabel *) _p->message_label, info.c_str());

  enable_button(_p);
}

/// \brief decrypt button's call back function
void decrypt_func(GtkWidget *widget, gpointer *data){

  //time start
  std::chrono::steady_clock::time_point  now = std::chrono::steady_clock::now();

  gp *_p = (gp *) data;
  disable_button(_p);

  const char *_file_path = gtk_entry_get_text((GtkEntry *)_p->file_entry);
  const char *_pwd = gtk_entry_get_text((GtkEntry *)_p->pwd_entry);

  std::string input_file_path(_file_path);
  std::string pwd(_pwd);

  if(input_file_path.empty() or pwd.empty()){
    gtk_label_set_text((GtkLabel *) _p->message_label, "\nFile path or password must not be empty.\n");
    enable_button(_p);
    return;
  }

  std::string output_file_path = input_file_path.substr(0,input_file_path.find_last_of('.'));
  output_file_path.insert(output_file_path.find_last_of('\\') + 1, "dec_");

  if(std::filesystem::exists(output_file_path)){
    gtk_label_set_text((GtkLabel *) _p->message_label, "\nDecrypted file already exists. Stop decrypt.\n");
    enable_button(_p);
    return;
  }

  gtk_label_set_text((GtkLabel *) _p->message_label, "\nDecrypting, do not close the window.\n");

  std::unique_ptr<FileEncrypter> _f(new FileEncrypter(input_file_path, output_file_path, pwd));

  try{
    _f->decrypt();
  } catch (file::NoEnoughSpace &e) {
    gtk_label_set_text((GtkLabel *) _p->message_label, "\nNo enough space to store encrypted file.\n");
    _f = nullptr;
    enable_button(_p);
    return;
  } catch (NotOurFile &e) {
    gtk_label_set_text((GtkLabel *) _p->message_label, "\nThis file is not our encrypted file.\n");
    _f = nullptr;
    enable_button(_p);
    return;
  } catch (WrongPassword &e) {
    gtk_label_set_text((GtkLabel *) _p->message_label, "\nWrong password.\n");
    _f = nullptr;
    enable_button(_p);
    return;
  }catch (FileBroken &e) {
    gtk_label_set_text((GtkLabel *) _p->message_label, "\nFile broken.\n");
    _f = nullptr;
    enable_button(_p);
    return;
  }

  _f = nullptr;

  // get time info
  auto t2 = std::chrono::steady_clock::now();
  std::chrono::duration<double> time_span =
      std::chrono::duration_cast<std::chrono::duration<double>>(t2 - now);

  std::string info("\nDecrypt finished using ");
  info.append(std::to_string(time_span.count()));
  info.append(" seconds.\n");

  gtk_label_set_text((GtkLabel *) _p->message_label, info.c_str());

  enable_button(_p);
}

void activate(GtkApplication *app, gpointer user_data) {
  GtkWidget *window;

  GtkWidget *grid;

  GtkWidget *encrypt_button;
  GtkWidget *decrypt_button;
  GtkWidget *select_file_button;
  GtkWidget *exit_button;

  GtkWidget *input_file_label;
  GtkWidget *pwd_label;
  GtkWidget *message_label;

  GtkWidget *input_file_entry;
  GtkWidget *pwd_entry;

#ifdef WIN32
  GFile *themefile;
  GtkCssProvider *provider;
  GdkScreen *screen;
  screen = gdk_screen_get_default();

  themefile = g_file_new_for_path(".\\share\\themes\\Qogir-manjaro-win-light\\gtk-3.0\\gtk.css");
  provider = gtk_css_provider_new();
  gtk_css_provider_load_from_file(provider, themefile, NULL);
  gtk_style_context_add_provider_for_screen(screen,
                                            GTK_STYLE_PROVIDER(provider),
                                            GTK_STYLE_PROVIDER_PRIORITY_USER);
  gtk_style_context_reset_widgets(screen);
#endif

  //create window object
  window = gtk_application_window_new(app);
  //set window title
  gtk_window_set_title(GTK_WINDOW (window), "FileEncrypter");
  //set window size
  gtk_window_set_default_size(GTK_WINDOW (window), 280, 50);
  gtk_window_set_position(GTK_WINDOW (window), GTK_WIN_POS_CENTER);
  gtk_window_set_resizable(GTK_WINDOW (window), FALSE);

  //create grid object
  grid = gtk_grid_new();
  gtk_container_set_border_width(GTK_CONTAINER(grid), 10);
  gtk_container_add(GTK_CONTAINER(window), grid);

  //create label object
  input_file_label = gtk_label_new("Input File:  ");
  pwd_label = gtk_label_new("Password:  ");
  message_label = gtk_label_new("\n\n\n");

  //create entry object
  input_file_entry = gtk_entry_new();
  pwd_entry = gtk_entry_new();

  //create button object and link call back function
  exit_button = gtk_button_new_with_label("Exit");
  g_signal_connect_swapped (exit_button,
                            "clicked",
                            G_CALLBACK(gtk_widget_destroy),
                            window);

  select_file_button = gtk_button_new_with_label("Select");
  g_signal_connect(select_file_button,
                   "clicked",
                   G_CALLBACK(select_file),
                   (gpointer) &p);

  encrypt_button = gtk_button_new_with_label("Encrypt");
  g_signal_connect(encrypt_button,
                   "clicked",
                   G_CALLBACK(encrypt_func),
                   (gpointer) &p);

  decrypt_button = gtk_button_new_with_label("Decrypt");
  g_signal_connect(decrypt_button,
                   "clicked",
                   G_CALLBACK(decrypt_func),
                   (gpointer) &p);

  //
  p.window = window;
  p.file_entry = input_file_entry;
  p.pwd_entry = pwd_entry;
  p.message_label = message_label;
  p.select_button = select_file_button;
  p.encrypt_button = encrypt_button;
  p.decrypt_button = decrypt_button;
  p.exit_button = exit_button;

  //put button and entry into grid
  gtk_grid_attach(GTK_GRID(grid), input_file_label, 0,0,2,1);
  gtk_grid_attach(GTK_GRID(grid), input_file_entry, 2,0,7,1);
  gtk_grid_attach(GTK_GRID(grid), select_file_button, 9,0,1,1);
  gtk_grid_attach(GTK_GRID(grid), pwd_label, 0,1,2,1);
  gtk_grid_attach(GTK_GRID(grid), pwd_entry, 2,1,8,1);

  gtk_grid_attach(GTK_GRID(grid), message_label, 0,2,10,2);

  gtk_grid_attach(GTK_GRID(grid), encrypt_button, 1,4,2,1);
  gtk_grid_attach(GTK_GRID(grid), decrypt_button, 3,4,2,1);
  gtk_grid_attach(GTK_GRID(grid), exit_button, 9,4,1,1);

  //show window
  gtk_widget_show_all(window);
}

int main(int argc, char **argv) {
  GtkApplication *app;
  int status;

  app = gtk_application_new("org.gtk.fileencrypter", G_APPLICATION_FLAGS_NONE);
  g_signal_connect (app, "activate", G_CALLBACK(activate), NULL);
  status = g_application_run(G_APPLICATION (app), argc, argv);
  g_object_unref(app);

  return status;
}
