
#if defined(ARDUINO) && ARDUINO >= 100
#include "Arduino.h"
#else
#include "WProgram.h"
#endif


#include "MessageEncoder.h"



void MessageEncoder::setEncoding (uint8_t SenderID, uint16_t maxMessageSize, StringEncryption *Encrypter) {
  AES = Encrypter;
  _SenderID = SenderID;
  _maxEncodedLength = maxMessageSize;
}


bool MessageEncoder::Encode(encoding_inputs* Input, String* Message) {

  // Copy input to encoding_data
  Encoding_Data.HeaderBlock.Components.SenderID = _SenderID;
  Encoding_Data.HeaderBlock.Components.MessageID = Input->MessageID;
  Encoding_Data.HeaderBlock.Components.Flag.Encrypted = Input->Encrypt;
  Encoding_Data.HeaderBlock.Components.Flag.needACK = Input->needACK;
  Encoding_Data.HeaderBlock.Components.Flag.isACK = Input->isACK;
  Encoding_Data.DataBlock.Components.ClearText = Input->Data;


  constructDataBlock();  // Create Data Block

  constructHeaderBlock();  // Create Header

  // Assemble the Message
  String Msg = "";
  Msg += char(2);
  Msg += char(13);
  Msg += Encoding_Data.HeaderBlock.HeaderBlock_String;  // 6 Bytes
  Msg += Encoding_Data.DataBlock.DataBlock_String;  // min 16 Bytes
  Msg += char(3);
  Msg += char(13);

  Encoding_Data.CompleteMessage = Msg;


  // Check max message length
  if (Encoding_Data.HeaderBlock.Components.DataBlockLength.DataBlockLength + 10  >  _maxEncodedLength) {
    *Message = "";
    return false;
  }


  *Message = Encoding_Data.CompleteMessage;
  return true;

}


bool MessageEncoder::Decode(String* Message, decoding_outputs* Output) {

  Decoding_Data.CompleteMessage = *Message;

  if (!splitMessage()) {
    return false;
  }

  if (!destructHeaderBlock()) {
    return false;
  }

  if (!destructDataBlock()) {
    return false;
  }
  
  Output->SenderID = Decoding_Data.HeaderBlock.Components.SenderID;
  Output->MessageID = Decoding_Data.HeaderBlock.Components.MessageID;
  Output->wasEncrypted = Decoding_Data.HeaderBlock.Components.Flag.Encrypted;
  Output->needACK = Decoding_Data.HeaderBlock.Components.Flag.needACK;
  Output->isACK = Decoding_Data.HeaderBlock.Components.Flag.isACK;
  Output->Data = Decoding_Data.DataBlock.Components.ClearText;

  return true;
}






uint8_t MessageEncoder::CRC8(String input) {
    // Pre-calculated CRC table for CRC-8 (polynomial 0x07)
    static const uint8_t crcTable[] = {
        0x00, 0x07, 0x0E, 0x09, 0x1C, 0x1B, 0x12, 0x15,
        0x38, 0x3F, 0x36, 0x31, 0x24, 0x23, 0x2A, 0x2D,
        0x70, 0x77, 0x7E, 0x79, 0x6C, 0x6B, 0x62, 0x65,
        0x48, 0x4F, 0x46, 0x41, 0x54, 0x53, 0x5A, 0x5D,
        0xE0, 0xE7, 0xEE, 0xE9, 0xFC, 0xFB, 0xF2, 0xF5,
        0xD8, 0xDF, 0xD6, 0xD1, 0xC4, 0xC3, 0xCA, 0xCD,
        0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85,
        0xA8, 0xAF, 0xA6, 0xA1, 0xB4, 0xB3, 0xBA, 0xBD,
    };

    uint8_t crc = 0;
    for (char ch : input) {
        crc = crcTable[crc ^ static_cast<uint8_t>(ch)];
    }

    return crc;
}


uint16_t MessageEncoder::CRC16(String input) {
    // Pre-calculated CRC table for CRC-16 (polynomial 0x8005)
    static const uint16_t crcTable[] = {
        0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
        0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
        0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
        0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
        0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
        0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
        0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
        0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
        0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
        0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
        0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
        0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
        0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
        0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
        0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
        0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    };

    uint16_t crc = 0xFFFF;
    for (char ch : input) {
        crc = (crc >> 8) ^ crcTable[(crc & 0xFF) ^ static_cast<uint8_t>(ch)];
    }

    return crc;
}




void MessageEncoder::constructHeaderBlock() {

  Encoding_Data.HeaderBlock.Components.Flag.Bit8 = true; // to avoid the flag byte from beeing \0

  // Single bytes to Byte-array
  uint8_t HeaderBytes[5] = { };
  HeaderBytes[0] = Encoding_Data.HeaderBlock.Components.SenderID;
  HeaderBytes[1] = Encoding_Data.HeaderBlock.Components.MessageID;
  HeaderBytes[2] = Encoding_Data.HeaderBlock.Components.Flag.Flag_Byte;
  HeaderBytes[3] = Encoding_Data.HeaderBlock.Components.DataBlockLength.LowerDBL_Byte;
  HeaderBytes[4] = Encoding_Data.HeaderBlock.Components.DataBlockLength.UpperDBL_Byte;

  // Byte-array to string
  String HeaderString = "";
  for (int i = 0; i < 5; i++) {
      HeaderString += (char)HeaderBytes[i];
  }

  // Calculate CRC
  Encoding_Data.HeaderBlock.Components.HeaderCRC = CRC8(HeaderString);  

  // Add CRC to String
  HeaderString += (char)Encoding_Data.HeaderBlock.Components.HeaderCRC;


  Encoding_Data.HeaderBlock.HeaderBlock_String = HeaderString;
}


bool MessageEncoder::destructHeaderBlock() {

  if (Decoding_Data.HeaderBlock.HeaderBlock_String.length() != 6) {  // Check if header is 6 bytes long
    return false;
  }

  Decoding_Data.HeaderBlock.Components.HeaderCRC = Decoding_Data.HeaderBlock.HeaderBlock_String[5];  // Get CRC from header

  Decoding_Data.HeaderBlock.HeaderBlock_String.remove(5);  // Remove CRC from header

  if (Decoding_Data.HeaderBlock.Components.HeaderCRC != CRC8(Decoding_Data.HeaderBlock.HeaderBlock_String)) {  // Check received CRC against calculated CRC
    return false;
  }
 


   //String to byte array
  uint8_t Bytes[5];
  for (int i = 0; i < 5; i++) {    
    Bytes[i] = (uint8_t)Decoding_Data.HeaderBlock.HeaderBlock_String.charAt(i);
  }


  Decoding_Data.HeaderBlock.Components.SenderID = Bytes[0];
  Decoding_Data.HeaderBlock.Components.MessageID = Bytes[1];
  Decoding_Data.HeaderBlock.Components.Flag.Flag_Byte = Bytes[2];
  Decoding_Data.HeaderBlock.Components.DataBlockLength.LowerDBL_Byte = Bytes[3];
  Decoding_Data.HeaderBlock.Components.DataBlockLength.UpperDBL_Byte = Bytes[4];


  return true;
}




void MessageEncoder::constructDataBlock() {

  Encoding_Data.DataBlock.Components.DataCRC.DataCRC = CRC16(Encoding_Data.DataBlock.Components.ClearText);    // Calculate CRC16


  // Put Data and CRC together
  String DataBlock = "";
  DataBlock += Encoding_Data.DataBlock.Components.ClearText;
  DataBlock += (char)Encoding_Data.DataBlock.Components.DataCRC.LowerCRC_Byte;
  DataBlock += (char)Encoding_Data.DataBlock.Components.DataCRC.UpperCRC_Byte;


  // Encrypt if needed
  if (Encoding_Data.HeaderBlock.Components.Flag.Encrypted) {
    DataBlock = AES->EncryptString(DataBlock);
  }


  Encoding_Data.DataBlock.DataBlock_String = DataBlock;
  Encoding_Data.HeaderBlock.Components.DataBlockLength.DataBlockLength = Encoding_Data.DataBlock.DataBlock_String.length();
}


bool MessageEncoder::destructDataBlock() {

  // check if real length matches length from header
  if (Decoding_Data.DataBlock.DataBlock_String.length() != Decoding_Data.HeaderBlock.Components.DataBlockLength.DataBlockLength) {
    return false;
  }


  // Decrypt if needed
  if (Decoding_Data.HeaderBlock.Components.Flag.Encrypted) {
    Decoding_Data.DataBlock.DataBlock_String = AES->DecryptString(Decoding_Data.DataBlock.DataBlock_String);
  }


  int lastIndex = Decoding_Data.DataBlock.DataBlock_String.length() - 1;

  Decoding_Data.DataBlock.Components.DataCRC.LowerCRC_Byte = Decoding_Data.DataBlock.DataBlock_String.charAt(lastIndex - 1);
  Decoding_Data.DataBlock.Components.DataCRC.UpperCRC_Byte = Decoding_Data.DataBlock.DataBlock_String.charAt(lastIndex);

  Decoding_Data.DataBlock.DataBlock_String.remove(lastIndex - 1);


  if (Decoding_Data.DataBlock.Components.DataCRC.DataCRC != CRC16(Decoding_Data.DataBlock.DataBlock_String)) {  // Check received CRC against calculated CRC
    return false;
  }


  Decoding_Data.DataBlock.Components.ClearText = Decoding_Data.DataBlock.DataBlock_String;

  return true;
}




byte MessageEncoder::findCharLocations(String& inp, char findIt, int (&resultList)[50]) {

    int InputSize = inp.length();
    int resultIndex = 0;

    for(int i = 0; i <= InputSize; i++) {

        if(inp[i] == findIt) {
            resultList[resultIndex] = i;
            resultIndex++;
        }
    }

    return resultIndex;
}


bool MessageEncoder::splitMessage() {

  int HeaderStartIndex = 0;
  int HeaderEndIndex = 0;
  int DataStartIndex = 0;
  int DataEndIndex = 0;

  // find all char(13)
  const int Char13Size = 50;
  int Char13Pos[Char13Size] = {};
  byte lastUsedArrayIndex = findCharLocations(Decoding_Data.CompleteMessage, char(13), Char13Pos);



  for (int i = 0;  i < Char13Size;  i++) {  // Surch for char(2) char(13) combination (before header)

    if (Decoding_Data.CompleteMessage.charAt(Char13Pos[i] - 1) == char(2) ) {
      HeaderStartIndex = Char13Pos[i] + 1;
      HeaderEndIndex = Char13Pos[i] + 7;
      DataStartIndex = Char13Pos[i] + 7;
      break;
    }
  }

  
  for (int i = lastUsedArrayIndex;  i >= 0;  i--) {  // Surch for char(3) char(13) combination (after data)

    if (Decoding_Data.CompleteMessage.charAt(Char13Pos[i] - 1) == char(3) ) {
      DataEndIndex = Char13Pos[i] - 1;
      break;
    }
  }


  // Check if indices were correctliy gathered
  if (HeaderStartIndex == 0 or HeaderEndIndex == 0 or DataStartIndex == 0 or DataEndIndex == 0) {
    return false;
  }


  // Get the header and data-block from the message
  Decoding_Data.HeaderBlock.HeaderBlock_String = Decoding_Data.CompleteMessage.substring(HeaderStartIndex, HeaderEndIndex);
  Decoding_Data.DataBlock.DataBlock_String = Decoding_Data.CompleteMessage.substring(DataStartIndex, DataEndIndex);

  return true;
}
