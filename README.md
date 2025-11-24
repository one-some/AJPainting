# AJPainting
Convert between .ajart and .png files.

## Warning
**Using this project is inherently dangerous!**
This project mocks user login flow to get the UUID, and is not very sneaky about it. Probably against AJ TOS, and I wouldn't be surprised if you get banned for it.

If you choose to use it, take a peek at the source code before putting your credentials in.

## Usage
`python painting.py username:password targetfilename.png/.ajart`

## Requirements
pycryptodome!
`pip install pycryptodome`

## Credits
The file format was mapped out entirely by V31L! Check out their project:
https://github.com/v31l-sys/ajart-studio-edit

This project was just made as an excercise and to streamline UUID obtaining.
