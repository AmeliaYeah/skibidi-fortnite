//return 1 for failure, 0 for success
void check(char *passwd)

{
  size_t pass_len;
  undefined8 failure;
  size_t sVar3;
  undefined8 local_58;
  undefined7 local_50;
  undefined uStack_49;
  undefined7 uStack_48;
  uint local_34;
  uint local_30;
  undefined4 local_2c;
  int j;
  uint i;
  int current_bit;
  int current_pwd_char;
  
  pass_len = strlen(passwd);
  if (pass_len == 0x1b) {
    local_58 = 0x617b2375f81ea7e1;
    local_50 = 0x69df5b5afc9db9;
    uStack_49 = 0xd2;
    uStack_48 = 0xf467edf4ed1bfe;
    current_pwd_char = 0;
    current_bit = 0;
    local_2c = 0;
    for (i = 0; i < 0x17; i = i + 1) {
      for (j = 0; j < 8; j = j + 1) {
        if (current_bit == 0) {
          current_bit = 1;
        }

        local_30 = 1 << (7 - (char)j & 0x1f);
        local_34 = 1 << (7 - (char)current_bit & 0x1f);

        //the check happens here
        if (0 < (passwd[current_pwd_char] & local_34) !=
            0 < (int)((int)*(char *)((long)&local_58 + (long)(int)i) & local_30)) {
          return 1;
        }

        current_bit++;
        if (current_bit == 8) {
          current_bit = 0;
          current_pwd_char++;
        }

        sVar3 = (size_t)current_pwd_char;
        pass_len = strlen(passwd);
        if (sVar3 == pass_len) {
          return 0;
        }
      }
    }
    failure = 0;
  }
  else {
    failure = 1;
  }
  return failure;
}

