#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include "cJSON.h"
#include "jsmn.h"
#include "app.h"

bool create_student_json(char * name, char * uin) {
  cJSON * student = cJSON_CreateObject();
  cJSON * name_obj = cJSON_CreateString(name);
  cJSON * uin_obj = cJSON_CreateString(uin);
  bool add_field_success = (
    cJSON_AddItemToObject(student, "Name", name_obj) && 
    cJSON_AddItemToObject(student, "UIN", uin_obj)
  );
  if (add_field_success) {
    if (json_student_buffer != NULL) {
      free(json_student_buffer);
    }  
    json_student_buffer = cJSON_Print(student);
  }
  cJSON_Delete(student);
  return add_field_success;
}

bool encrypt_and_save_json_student(char * txt_file_out) {
  bool success = (
    copy_to_decrypted_buffer(json_student_buffer, strlen(json_student_buffer)) &&
    enclave_encrypt_aes() &&
    save_text(encrypted_message_buffer, get_encrypted_buffer_size(), txt_file_out)
  );
  return success;
}

bool load_and_decrypt_json_student(char * txt_file_in) {
  size_t text_size;
  char text[encrypt_decrypt_message_size];
  memset(text, 0, encrypt_decrypt_message_size);

  bool success = (
    load_text(txt_file_in, text, &text_size) &&
    copy_to_encrypted_buffer(text, text_size) &&
    enclave_decrypt_aes() &&
    memset(json_student_buffer, 0, strlen(decrypted_message_buffer) + 1) &&
    memcpy(json_student_buffer, decrypted_message_buffer, strlen(decrypted_message_buffer))
  );
  return success;
}

bool add_string_field_to_student(char * field_name, char * field_val) {
  cJSON * field_val_json = cJSON_CreateString(field_val);
  cJSON * student = cJSON_Parse(json_student_buffer);
  bool field_exists = cJSON_HasObjectItem(student, field_name);
  bool update_success = true;
  if (field_exists) {
    update_success = cJSON_ReplaceItemInObjectCaseSensitive(student, field_name, field_val_json);
  } else {
    update_success = cJSON_AddItemToObject(student, field_name, field_val_json);
  }
  if (!update_success) return 0;
  char * new_student_string = cJSON_Print(student);
  memset(json_student_buffer, 0, strlen(new_student_string) + 1);
  memcpy(json_student_buffer, new_student_string, strlen(new_student_string));
  free(new_student_string);
  cJSON_Delete(student);
  return 1;
}

bool test_json(char * s) {

  jsmn_parser p;
  jsmntok_t t[128]; /* We expect no more than 128 JSON tokens */

  jsmn_init(&p);
  int r = jsmn_parse(&p, s, strlen(s), t, 128); // "s" is the char array holding the json content
  for (int i = 0; i < r - 1; i++) {
    if (t[i].type == 1) {
      printf("\n OBJECT");
    } else if (t[i].type == 2) {
      printf("\n ARRAY");
    } else if (t[i].type == 4) {
      printf("\n STRING");
    } else if (t[i].type == 8) {
      printf("\n PRIMITIVE");
    }
    printf("\n token start %u %u \n", t[i].start, t[i].end);
    for (int j = t[i].start; j < t[i].end; j++) {
      printf("%c", s[j]);
    }
    printf("\n");
    if (t[i].type == JSMN_STRING && t[i + 1].type == JSMN_ARRAY && t[i].end - t[i].start == 9) {
      bool test = true;
      char user_data[10] = "user_data";
      for (int j = 0; j < 9; j++) {
        if (s[t[i].start + j] != user_data[j]) {
          test = false;
          break;
        }
      }
      if (test) {
        int array_start = t[i + 1].start;
        int array_end = t[i + 1].end;
        // if array is empty
        if (array_end - array_start <= 2) {
          char new_user[100] = "{\"0\":{\"test_history\": \"\", \"query_counter\": 0}}";
          char new_enclave_state[2048];
          for (int i = 0; i <= array_start; i++) {
            new_enclave_state[i] = s[i];
          }
          for (int i = 0; i < strlen(new_user); i++) {
            new_enclave_state[i + array_start + 1] = new_user[i];
          }
          for (int i = 0; i < strlen(s) - array_end + 1; i++) {
            new_enclave_state[i + array_start + strlen(new_user) + 1] = s[i + array_end - 1];
          }
          new_enclave_state[strlen(s) - array_end + 1 + array_start + strlen(new_user) + 1] = 0;
        } else {
          // get the ID of the last user JSON object
          int last_object_idx = i + 2;
          int index_count = i + 2;
          while (true) {
            if (t[index_count].end >= array_end) {
              break;
            }
            if (t[index_count].type == JSMN_OBJECT) {
              last_object_idx = index_count;
            }
            index_count++;
          }
          // get the value of the last user uuid (get the string of the last user uuid and cast to int)
          int last_uuid_start = t[last_object_idx - 1].start;
          int last_uuid_end = t[last_object_idx - 1].end;
          int last_uuid = 0;
          for (int j = last_uuid_start; j < last_uuid_end; j++) {
            last_uuid = 10 * last_uuid + (s[j] - '0');
          }
          // increment the last user id to get the new user id and cast back to string
          int new_user_id = last_uuid + 1;
          int num_digits = 0;
          int new_user_id_temp = new_user_id;
          while (new_user_id_temp > 0) {
            new_user_id_temp /= 10;
            num_digits++;
          }
          char new_user_id_str[num_digits + 1];
          for (int j = num_digits - 1; j >= 0; --j, new_user_id /= 10) {
              new_user_id_str[j] = (new_user_id % 10) + '0';
          }
          char new_user_first_part[3] = "{\"";
          char new_user_last_part[100] = "\":{\"test_history\": \"\", \"query_counter\": 0}}";
          char new_user[100];
          for (int i = 0; i < strlen(new_user_first_part); i++) {
            new_user[i] = new_user_first_part[i];
          }
          for (int i = 0; i < strlen(new_user_id_str); i++) {
            new_user[i + strlen(new_user_first_part)] = new_user_id_str[i];
          }
          for (int i = 0; i < strlen(new_user_last_part); i++) {
            new_user[i + strlen(new_user_first_part) + strlen(new_user_id_str)] = new_user_last_part[i];
          }
          new_user[strlen(new_user_first_part) + strlen(new_user_id_str) + strlen(new_user_last_part)] = 0;
          
          // add this new_user string to the enclave state
          char new_enclave_state[2048];
          for (int i = 0; i < array_end - 1; i++) {
            new_enclave_state[i] = s[i];
          }
          new_enclave_state[array_end - 1] = ',';
          new_enclave_state[array_end] = ' ';
          for (int i = 0; i < strlen(new_user); i++) {
            new_enclave_state[i + array_end + 1] = new_user[i];
          }
          for (int i = 0; i < strlen(s) - array_end + 1; i++) {
            new_enclave_state[i + array_end + 1 + strlen(new_user)] = s[i + array_end - 1];
          }
          new_enclave_state[strlen(s) - array_end + 1 + array_end + 1 + strlen(new_user)] = 0;
        }
      }
    }
  }

  uint8_t x[1] = {0xAB};
  printf("\n test sha \n");
  printf("%x %x", (x[0] & 0x0F), ((x[0] >> 4) & 0x0F));
}