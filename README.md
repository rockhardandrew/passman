# Passman: simple secure password manager
I wrote this project awhile back but I still use it on a daily basis as my main password manager. Code might be a little janky that's how it goes when it's a 12 year old writing C code. Still works well.
## Installation
Note that passman only runs on Linux and BSD(OpenBSD, FreeBSD, NetBSD, DragonFlyBSD and very likely Macos)
``
make
doas make install
``
then you have it installed.
### ksh completion
There's ksh configuration written for passman, to install just run `cat ksh-completion >> ~/.kshrc`
## Usage
* `passman init`:    creates the .passman-store directory and the encryption key, only 1 arg required
* `passman generate [name] [length]`:   generates a password and securely stores it, requires 3 arguments
* `passman show [name]`:    gets and prints a stored password, two args required(show [name])
* `passman insert/add [name]`  prompts you for a password and securely stores it
* `passman list`     walks the ~/.passman-store directory
