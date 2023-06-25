/*
 * This file is part of the Arduino UNO Password Lock
 * Copyright (c) 2023 Jan Novotný.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <Keypad.h>
#include <LiquidCrystal_I2C.h>
#include <XxHash_arduino.h>
#include <EEPROM.h>

#define RELAY 13
#define PASS_LIMIT 10 // limit of passwords
#define HASH_SIZE 9
#define MAGIC 32
#define RESET_BUT 10

// Lock states, pretty obvious
enum states {initial, locked, unlocked, menu, timeout};

// Different menu states
enum menu_states {main,
                  add_pin,
                  remove_pin,
                  timeout_toggle,
                  set_timeout,
                  set_pin_len,
                  clear_pins,
                  set_fail_limit,
                  set_fail_timeout
                 };


// ugly - custom input digit length for some functions, 0 to use pin length
byte cursor_limits[] = {
  0, // main
  0, // add_pin
  0, // remove_pin
  0, // timeout_toggle
  4, // set_timeout
  1, // set_pin_len
  0, // clear_pins
  3, // set_fail_limit
  4  // set_fail_timeout
};


// ...and their corresponding strings
// the 2 arrays should follow the same order
const char* menu_items[] =
{ "add PIN",       // add_pin
  "remove PIN",    // remove_pin
  "timeout mode",  // timeout_toggle
  "set timeout",   // set_timeout
  "set PIN len",   // set_pin_len
  "clear PINs",    // clear_pins
  "set try limit", // set_fail_limit
  "fail timeout"   // set_fail_timeout
};
const byte menu_len = sizeof(menu_items) / sizeof(char*);

// State of the lock
struct state {
  uint32_t _magic;    // special magic number, stored for some fancy tricks!
  byte pin_len;       // Length of PIN code
  byte pass_index;    // number of filled passwords
  byte cursor_index;  // cursor position on input, also the index in the menu
  bool wait;          // timeout bool, will lock after set time if true
  enum states state;  // lock state
  long timer;         // used for timers
  long wait_ms;       // time to wait before re-locking
  enum menu_states menu_state; // menu state selection
  char passwords[PASS_LIMIT][HASH_SIZE]; // valid password array
  bool redraw; // used to force a menu redraw, might not be necessary
  byte failed; // counts failed PIN attempts
  byte failed_max; // failed attempts before timeout
  long failed_wait_ms; // time to wait after x failed attempts
  bool failed_check; // enable or disable login timeouts
  char* guess; // user's current input, usually a guess
};

const byte rows              = 4;
const byte cols              = 4;
const byte colPins[rows]     = {5, 4, 3, 2};
const byte rowPins[cols]     = {9, 8, 7, 6};
const byte lcd_addr          = 0x27;
const byte lcd_cols          = 20;
const byte lcd_rows          = 4;

const char keys[rows][cols] = {
  {'1', '2', '3', 'A'},
  {'4', '5', '6', 'B'},
  {'7', '8', '9', 'C'},
  {'*', '0', '#', 'D'}
};

Keypad keypad = Keypad(
                  makeKeymap(keys),
                  rowPins,
                  colPins,
                  rows,
                  cols
                );

LiquidCrystal_I2C lcd = LiquidCrystal_I2C(lcd_addr, lcd_cols, lcd_rows);

// center text in row, forcefully overwrites all existing text
void lcd_center(char* str, int row) {
  static char n[lcd_cols+1];
  for (int i = 0; i < lcd_cols; i++) {
    n[i] = ' ';
  }
  for (int i = 0; i < strlen(str); i++) {
    n[lcd_cols / 2 - (strlen(str)+0) / 2 + i] = str[i];
  }
  n[lcd_cols] = '\0';
  lcd.setCursor(0, row);
  lcd.print(n);
}

// init str as '----', will alloc str if NULL
char* make_input_str(char* str = NULL, byte strlen = 9) {
  if (str == NULL)
    str = (char*)malloc(sizeof(char) * (strlen + 1));
  for (int i = 0; i < strlen; i++) {
    str[i] = '-';
  }
  str[strlen] = '\0';
  return str;
}

// too lazy to make a full header file so I just declare these for the init function
void switch_state(struct state* state, enum states s, byte digits = 0);
void switch_menu_state(struct state* state, enum menu_states s, byte digits = 0);

// lock initialization
struct state* init_lock(bool skip_eeprom = false) {
  struct state* state = (struct state*)malloc(sizeof(struct state));

  state->guess = make_input_str(); // alloc input str, not saved in EEPROM

  uint32_t magic;
  EEPROM.get(512, magic); // get magic number

  if (magic == MAGIC && !skip_eeprom) { // if magic is 32 it means the lock state has been written to EEPROM so we can read it
    eeprom_read_state(512, state);
    switch_state(state, state->state); // ensure all the needed operations are executed
    switch_menu_state(state, state->menu_state);
  } // there is a 1 in 2147483647 chance of a false positive
  else { // otherwise init defaults
    state->pin_len = 4;
    state->wait = true;
    state->pass_index = 0;
    state->_magic = (int)MAGIC;
    state->cursor_index = 0;
    state->failed_max = 3;
    state->redraw = true;
    state->failed_wait_ms = 15000;
    state->failed_check = true;
    state->wait_ms = 15000;
    state->failed = 0;

    switch_state(state, menu); // ensure all the needed operations are executed
    switch_menu_state(state, add_pin);
  }
  state->timer = 0;

  return state;
}

// write entire state struct to addr
void eeprom_write_state(uint16_t addr, struct state* state) {
  EEPROM.put(addr, *state);
}

// read entire state struct from addr
// TODO: no memory corruption checks, potentially use checksum to verify correctness
void eeprom_read_state(uint16_t addr, struct state* state) {
  /*for (size_t i = 0; i < sizeof(struct state); i++) {
    memset(state + i, (void*)EEPROM.read(addr + i), 1);
  }*/
  EEPROM.get(addr, state);
}

// convert input to int; '60--' -> 60
int int_from_pinstr(char* str) {
  int r = 0;
  const int len = strlen(str);
  for (int i = 0; str[i] != '-' && i < len; i++) {
    r = r * 10 + (str[i] - 48);
  }
  if (strlen(str))
    return r;
  else
    return 5;
}

// add a PIN to the list
byte add_pass(struct state* state, char* str) {
  if (state->pass_index >= PASS_LIMIT) {
    state->pass_index = PASS_LIMIT;
    return 1;
  }
  xxh32(state->passwords[state->pass_index], str); // PINs are hashed, allows using arbitrary PIN length
  state->passwords[state->pass_index][HASH_SIZE - 1] = '\0';
  state->pass_index++;
  return 0;
}

// verify corectness of a PIN by checking its hash against valid PINs
bool is_pass_right(struct state* state, char* str) {
  char hash[HASH_SIZE];
  xxh32(hash, str);
  hash[HASH_SIZE - 1] = '\0';
  for (byte i = 0; i < state->pass_index; i++) {
    if (!(strcmp(hash, state->passwords[i])))
      return true;
  }
  return false;
}

// remove a PIN by index
byte remove_pass(struct state* state, byte index) {
  if (index >= state->pass_index)
    return 1;
  for (byte i = index + 1; i < state->pass_index; i++) {
    strncpy(state->passwords[i - 1], state->passwords[i], HASH_SIZE);
  }
  state->pass_index--;
}

// remove a PIN by str value
byte remove_pass_str(struct state* state, const char* str) {
  char hash[HASH_SIZE];
  xxh32(hash, str);
  hash[HASH_SIZE - 1] = '\0';
  for (byte i = 0; i < state->pass_index; i++) {
    if (!(strcmp(hash, state->passwords[i])))
      return remove_pass(state, i);
  }
  return 1;
}

// clear all PINs
void clear_passwords(struct state* state) {
  state->pass_index = 0;
}

// UNUSED: write state into memory
void write_state(struct state* state, void* dest) {
  memcpy(dest, state, sizeof(struct state));
}

// UNUSED: read state from memory
void read_state(void* dest, void* data) {
  memcpy(dest, data, sizeof(struct state));
}

// set the timer
void set_timer_ms(struct state* state, long ms) {
  state->timer = millis() + ms;
}

// check if timer has elapsed
bool timer_done(struct state* state) {
  return state->timer <= millis();
}

// return a string of time left on timer
char* make_countdown_str(struct state* state) {
  static long t = 0;
  static long l = 0;
  static char* t_str = (char*)malloc(sizeof(char) * 10);

  t = state->timer - millis();
  t /= 1000;
  if (l != t) {
    ltoa(t, t_str, 10); // print countdown
    t_str[9] = '\0';
  }
  l = t;

  return (t_str);
}

// clear current input
void clear_guess(struct state* state, byte digits = 0) {
  if (!digits) digits = state->pin_len;
  state->cursor_index = 0;
  state->guess = make_input_str(state->guess);
  state->guess[digits] = '\0';
}

// toggle the timeout feature
void toggle_timeout(struct state* state) {
  state->wait = !(state->wait);
}

// render the appropriate menu item selected with state->cursor_index
//   has autoscroll too
void render_menu(struct state* state) {
  static byte last = 0;
  static byte n_i, c_pos;

  if (last != state->cursor_index || state->redraw) {
    lcd.clear();
    n_i = state->cursor_index;
    if (state->cursor_index >= menu_len - lcd_rows) n_i = menu_len - lcd_rows;
    for (int i = 0; i < lcd_rows; i++) {
      lcd.setCursor(3, i);
      lcd.print(menu_items[n_i + i]);
    }

    c_pos = state->cursor_index - n_i;
    lcd.setCursor(0, c_pos);
    lcd.write('-');
    lcd.write('>');
  }
  if (state->redraw) state->redraw = false;
  last = state->cursor_index;
}

// change lock state
void switch_state(struct state* state, enum states s, byte digits = 0) {
  state->state = s;
  clear_guess(state, digits);
  lcd.clear();
}

// check if the input filed is entirely filled in
bool input_is_filled(struct state* state) {
  return state->cursor_index == state->pin_len;
}

// change menu state
void switch_menu_state(struct state* state, enum menu_states s, byte digits = 0) {
  state->menu_state = s;
  state->redraw = true;
  digits = cursor_limits[(byte)s];
  if (!digits) digits = state->pin_len;
  clear_guess(state, digits);
  lcd.clear();
}

// push a new number and move cursor
void push_number(struct state* state, char key, byte digits = 0) {
  if (!digits) digits = state->pin_len;
  if (state->cursor_index < digits) {
    state->guess[state->cursor_index++] = key; // add PIN digit
  }
}

void setup() {
  //Serial.begin(9600);
  lcd.begin(lcd_addr, lcd_cols, lcd_rows);
  lcd.setBacklight(100);
  lcd.clear();
  pinMode(RELAY, OUTPUT);
  pinMode(RESET_BUT, INPUT_PULLUP);
  digitalWrite(RELAY, HIGH);
}

void loop() {
  static struct state* state = init_lock();
  static char guess_hash[HASH_SIZE];
  static char key;

  if (digitalRead(RESET_BUT) == LOW) { // Complete lock reset secret button
    free(state->guess);
    free(state);
    state = init_lock(true); // skip reading from EEPROM on creating new state
  }

  // documentation says writes should only happen if the value has been updated,
  // so we shouldn't be killing the EEPROM this way
  eeprom_write_state(512, state);

  key = keypad.getKey();

  // * Unlocked state * ---------------------------------------------
  if (state->state == unlocked) {
    digitalWrite(RELAY, HIGH);
    lcd_center("* lock  # menu", lcd_rows/2-1);
    if (key == '*') {
      switch_state(state, locked);
      return;
    }
    else if (key == '#') { // open menu
      switch_state(state, menu);
      switch_menu_state(state, main);
      return;
    }
    if (state->wait) { // if timeout mode
      static char* t_str;
      t_str = make_countdown_str(state); // print countdown
      lcd_center(t_str, lcd_rows/2);
      if (timer_done(state)) {
        switch_state(state, locked);
        return;
      }
    }
    else { // if not in timeout mode just print "unlocked"
      lcd_center("unlocked", lcd_rows/2);
    }
  }
  // ----------------------------------------------------------------

  // * Locked state * -----------------------------------------------
  else if (state->state == locked) {
    digitalWrite(RELAY, LOW);
    lcd_center("locked", lcd_rows/2-1);
    if (isdigit(key)) {
      push_number(state, key);
    }
    else if (key == 'C') {
      clear_guess(state);
    }
    else if (key == 'D' && input_is_filled(state)) {
      if (is_pass_right(state, state->guess)) {
        set_timer_ms(state, state->wait_ms);
        state->failed = 0;
        switch_state(state, unlocked);
        return;
      }
      else {
        state->failed++;
        clear_guess(state);
        lcd.clear();
        lcd_center("incorrect!", lcd_rows/2-1);
        delay(2000);
        if (state->failed_max && state->failed >= state->failed_max) {
          set_timer_ms(state, state->failed_wait_ms);
          switch_state(state, timeout);
        }
        return;
      }
    }
    lcd_center(state->guess, lcd_rows/2);
  }
  // ----------------------------------------------------------------

  // * Login timeout state * ----------------------------------------
  else if (state->state == timeout) {
    lcd_center("locked", lcd_rows/2-1);
    static char* t_str;
    t_str = make_countdown_str(state);

    lcd_center(t_str, lcd_rows/2);

    if (timer_done(state)) {
      state->failed = 0;
      switch_state(state, locked);
      return;
    }
  }
  // ----------------------------------------------------------------


  else if (state->state == menu) {

    // * Main menu section --------------------------------------------
    if (state->menu_state == main) {
      if (key == 'B' && state->cursor_index + 1 < menu_len) {
        state->cursor_index++;
        state->redraw = true;
      }
      else if (key == 'A' && state->cursor_index > 0) {
        state->cursor_index--;
        state->redraw = true;
      }
      else if (key == 'A' && state->cursor_index == 0) { // wrap to bottom
        state->cursor_index = menu_len - 1;
        state->redraw = true;
      }
      else if (key == 'B' && state->cursor_index == menu_len - 1) { // wrap to top
        state->cursor_index = 0;
        state->redraw = true;
      }
      else if (key == 'D') {
        switch_menu_state(state, (enum menu_states)state->cursor_index + 1);
        return;
      }
      else if (key == '*') {
        switch_state(state, locked);
        return;
      }
      if (state->redraw) {
        render_menu(state);
        state->redraw = false;
      }
    }
    // ----------------------------------------------------------------

    // * Menu - Clear PINs * ------------------------------------------
    else if (state->menu_state == clear_pins) {
      clear_passwords(state);
      switch_menu_state(state, add_pin);
      state->cursor_index = 0; // 5
      return;
    }
    // ----------------------------------------------------------------

    // * Menu - Toggle Timeout mode * ---------------------------------
    else if (state->menu_state == timeout_toggle) {
      state->wait = !state->wait;
      lcd.clear();
      if (!state->wait)
        lcd_center("timeout: off", lcd_rows/2-1);
      else
        lcd_center("timeout: on", lcd_rows/2-1);
      delay(2000);
      switch_menu_state(state, main);
      state->cursor_index = 2; // lazy way to return to the correct menu index on submenu leave
      return;
    }
    // ----------------------------------------------------------------

    // * Menu - Add PIN  * --------------------------------------------
    else if (state->menu_state == add_pin) {
      lcd_center("Add PIN:", lcd_rows/2-1);
      if (isdigit(key)) {
        push_number(state, key);
      }
      else if (key == 'C') {
        clear_guess(state);
      }
      else if (key == 'D' && input_is_filled(state)) {
        byte excode = add_pass(state, state->guess);
        if (excode) {
          lcd_center("pass mem full!", lcd_rows/2);
          delay(2000);
        }
        switch_menu_state(state, main);
        state->cursor_index = 0;
        return;
      }
      lcd_center(state->guess, lcd_rows/2);
    }
    // -----------------------------------------------------------------

    // * Menu - Remove PIN  * ------------------------------------------
    else if (state->menu_state == remove_pin) {
      lcd_center("remove PIN:", lcd_rows/2-1);
      if (isdigit(key)) {
        push_number(state, key);
      }
      else if (key == 'C') {
        clear_guess(state);
      }
      else if (key == 'D' && input_is_filled(state)) {
        remove_pass_str(state, state->guess);
        switch_menu_state(state, main);
        state->cursor_index = 1;
        return;
      }
      lcd_center(state->guess, lcd_rows/2);
    }
    // -----------------------------------------------------------------

    // * Menu - Set PIN Lenght  * --------------------------------------
    else if (state->menu_state == set_pin_len) {
      lcd_center("Set PIN length:", lcd_rows/2-1);
      if (isdigit(key)) {
        push_number(state, key, 1);
      }
      else if (key == 'C') {
        clear_guess(state, 1);
      }
      else if (key == 'D') {
        byte plen = int_from_pinstr(state->guess);
        if (plen) {
          state->pin_len = plen;
          switch_menu_state(state, add_pin);
          return;
        }
      }
      lcd_center(state->guess, lcd_rows/2);
    }
    // ----------------------------------------------------------------

    // * Menu - Set Timeout * -----------------------------------------
    else if (state->menu_state == set_timeout) {
      lcd_center("Set timeout (s):", lcd_rows/2-1);
      if (isdigit(key)) {
        push_number(state, key, 4);
      }
      else if (key == 'C') {
        clear_guess(state, 4);
      }
      else if (key == 'D') {
        long n = ((int_from_pinstr(state->guess) + 1) * 1000L);
        state->wait_ms = n;
        switch_menu_state(state, main);
        state->cursor_index = 3;
        return;
      }
      lcd_center(state->guess, lcd_rows/2);
    }
    // ----------------------------------------------------------------

    // * Menu - Set Fail Timeout * ------------------------------------
    else if (state->menu_state == set_fail_timeout) {
      lcd_center("Set timeout (s):", lcd_rows/2-1);
      if (isdigit(key)) {
        push_number(state, key, 4);
      }
      else if (key == 'C') {
        clear_guess(state, 4);
      }
      else if (key == 'D') {
        long n = ((int_from_pinstr(state->guess) + 1) * 1000L);
        state->failed_wait_ms = n;
        switch_menu_state(state, main);
        state->cursor_index = 7;
        return;
      }
      lcd_center(state->guess, lcd_rows/2);
    }
    // ----------------------------------------------------------------

    // * Menu - Set Fail Limit * --------------------------------------
    else if (state->menu_state == set_fail_limit) {
      lcd_center("Tries (0 off):", lcd_rows/2-1);
      if (isdigit(key)) {
        push_number(state, key, 3);
      }
      else if (key == 'C') {
        clear_guess(state, 3);
      }
      else if (key == 'D') {
        byte m = int_from_pinstr(state->guess);
        if (m) {
          state->failed_check = true;
          state->failed_max = m;
        }
        else {
          state->failed_check = false;
        }
        switch_menu_state(state, main);
        state->cursor_index = 6;
        return;
      }
      lcd_center(state->guess, lcd_rows/2);
    }
    // ----------------------------------------------------------------

  }
}
