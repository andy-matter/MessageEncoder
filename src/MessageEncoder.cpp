
#if defined(ARDUINO) && ARDUINO >= 100
#include "Arduino.h"
#else
#include "WProgram.h"
#endif


#include "MessageEncoder.h"



void MessageEncoder::setEncoding (uint8_t NetworkID, uint8_t SenderID, uint16_t maxMessageSize, const uint8_t *EnctyptionKey) {
  Encrypter.setup(EnctyptionKey, 32);
  _NetworkID = NetworkID;
  _SenderID = SenderID;
  _maxEncodedLength = maxMessageSize;
}





bool MessageEncoder::Encode(encoding_inputs* Input, String* Message) {

  // Copy input to encoding_data
  Encoding_Data.HeaderBlock.Components.NetworkID = _NetworkID + 1;
  Encoding_Data.HeaderBlock.Components.SenderID = _SenderID + 1;  // to avoid \0 bytes
  Encoding_Data.HeaderBlock.Components.ReceiverID = Input->ReceiverID + 1;
  Encoding_Data.HeaderBlock.Components.MessageID = Input->MessageID + 1;
  Encoding_Data.HeaderBlock.Components.Flag.Encrypted = Input->Encrypt;
  Encoding_Data.HeaderBlock.Components.Flag.needACK = Input->needACK;
  Encoding_Data.HeaderBlock.Components.Flag.isACK = Input->isACK;
  Encoding_Data.DataBlock.Components.ClearText = Input->Data;


  constructDataBlock();  // Create Data Block

  constructHeaderBlock();  // Create Header


  // Assemble the Message
  Encoding_Data.CompleteMessage = "";
  Encoding_Data.CompleteMessage += char(2);
  Encoding_Data.CompleteMessage += char(13);
  Encoding_Data.CompleteMessage += char(2);
  Encoding_Data.CompleteMessage += Encoding_Data.HeaderBlock.HeaderBlock_String;  // 8 Bytes
  Encoding_Data.CompleteMessage += Encoding_Data.DataBlock.DataBlock_String;  // min 16 Bytes
  Encoding_Data.CompleteMessage += char(3);
  Encoding_Data.CompleteMessage += char(13);
  Encoding_Data.CompleteMessage += char(3);


  *Message = "";

  // Check max message length
  if (Encoding_Data.CompleteMessage.length()  >  _maxEncodedLength) {
    return false;
  }


  *Message = Encoding_Data.CompleteMessage;
  return true;
}



bool MessageEncoder::Decode(String* Message, decoding_outputs* Output) {

  Decoding_Data.CompleteMessage = *Message;

  if (!splitMessage())  {return false;}

  if (!destructHeaderBlock())  {return false;}

  if (!destructDataBlock())  {return false;}

  if (_NetworkID != Decoding_Data.HeaderBlock.Components.NetworkID-1) {
    return false;
  }

  if (Decoding_Data.HeaderBlock.Components.ReceiverID-1  !=  0    ||    Decoding_Data.HeaderBlock.Components.ReceiverID-1  !=  _SenderID) {
    return false;
  }
  
  
  Output->SenderID = Decoding_Data.HeaderBlock.Components.SenderID - 1;
  Output->MessageID = Decoding_Data.HeaderBlock.Components.MessageID - 1;
  Output->wasEncrypted = Decoding_Data.HeaderBlock.Components.Flag.Encrypted;
  Output->needACK = Decoding_Data.HeaderBlock.Components.Flag.needACK;
  Output->isACK = Decoding_Data.HeaderBlock.Components.Flag.isACK;
  Output->Data = Decoding_Data.DataBlock.Components.ClearText;

  return true;
}






uint8_t MessageEncoder::CRC8(const String &input) {

  uint8_t crc = 0xFF; // Initial value, can be modified based on your requirements

  for (size_t i = 0; i < input.length(); ++i) {
    crc ^= input[i];

    for (int j = 0; j < 8; ++j) {
      if (crc & 0x01) {
        crc = (crc >> 1) ^ 0x8C; // 0x8C is the CRC polynomial, can be modified
      } else {
        crc >>= 1;
      }
    }
  }

  // Ensure the CRC value is not 0
  return (crc == 0) ? 0x01 : crc;
}



uint16_t MessageEncoder::CRC16(const String &input) {

  uint16_t crc = 0xFFFF; // Initial value, can be modified based on your requirements

  for (size_t i = 0; i < input.length(); ++i) {
    crc ^= (uint16_t)input[i] << 8;

    for (int j = 0; j < 8; ++j) {
      if (crc & 0x8000) {
        crc = (crc << 1) ^ 0x1021; // 0x1021 is the CRC polynomial (CCITT standard), can be modified
      } else {
        crc <<= 1;
      }
    }
  }

  // Ensure the CRC value is not 0
  return (crc == 0) ? 0x0001 : crc;
}





void MessageEncoder::constructHeaderBlock() {

  Encoding_Data.HeaderBlock.Components.Flag.Bit7 = true; // to avoid the flag byte from beeing \0

  if (Encoding_Data.HeaderBlock.Components.ReceiverID-1 == 0) {  // ACK request is not allowed for broadcast messages (due to network congestion when all receiver want to send ack at the  same time)
    Encoding_Data.HeaderBlock.Components.Flag.needACK = false;
  }

  // Single bytes to Byte-array
  uint8_t HeaderBytes[_HeaderSize-1] = { };
  HeaderBytes[0] = Encoding_Data.HeaderBlock.Components.NetworkID;
  HeaderBytes[1] = Encoding_Data.HeaderBlock.Components.SenderID;
  HeaderBytes[2] = Encoding_Data.HeaderBlock.Components.ReceiverID;
  HeaderBytes[3] = Encoding_Data.HeaderBlock.Components.MessageID;
  HeaderBytes[4] = Encoding_Data.HeaderBlock.Components.Flag.Flag_Byte;
  HeaderBytes[5] = Encoding_Data.HeaderBlock.Components.DataBlockLength.LowerDBL_Byte;
  HeaderBytes[6] = Encoding_Data.HeaderBlock.Components.DataBlockLength.UpperDBL_Byte;

  // Byte-array to string
  String HeaderString = "";
  for (int i = 0; i < _HeaderSize-1; i++) {
      HeaderString += (char)HeaderBytes[i];
  }

  // Calculate CRC
  Encoding_Data.HeaderBlock.Components.HeaderCRC = CRC8(HeaderString);

  // Add CRC to String
  HeaderString += (char)Encoding_Data.HeaderBlock.Components.HeaderCRC;


  Encoding_Data.HeaderBlock.HeaderBlock_String = HeaderString;
}



bool MessageEncoder::destructHeaderBlock() {

  if (Decoding_Data.HeaderBlock.HeaderBlock_String.length() != _HeaderSize) {  // Check if header is expectet length
    return false;
  }

  Decoding_Data.HeaderBlock.Components.HeaderCRC = Decoding_Data.HeaderBlock.HeaderBlock_String[_HeaderSize-1];  // Get CRC from header

  Decoding_Data.HeaderBlock.HeaderBlock_String.remove(_HeaderSize-1);  // Remove CRC from header

  if (Decoding_Data.HeaderBlock.Components.HeaderCRC != CRC8(Decoding_Data.HeaderBlock.HeaderBlock_String)) {  // Check received CRC against calculated CRC
    return false;
  }
 


  //String to byte array
  uint8_t Bytes[_HeaderSize-1];
  for (int i = 0; i < _HeaderSize-1; i++) {    
    Bytes[i] = (uint8_t)Decoding_Data.HeaderBlock.HeaderBlock_String.charAt(i);
  }


  Decoding_Data.HeaderBlock.Components.NetworkID = Bytes[0];
  Decoding_Data.HeaderBlock.Components.SenderID = Bytes[1];
  Decoding_Data.HeaderBlock.Components.ReceiverID = Bytes[2];
  Decoding_Data.HeaderBlock.Components.MessageID = Bytes[3];
  Decoding_Data.HeaderBlock.Components.Flag.Flag_Byte = Bytes[4];
  Decoding_Data.HeaderBlock.Components.DataBlockLength.LowerDBL_Byte = Bytes[5];
  Decoding_Data.HeaderBlock.Components.DataBlockLength.UpperDBL_Byte = Bytes[6];

  return true;
}





void MessageEncoder::constructDataBlock() {

  Encoding_Data.DataBlock.Components.DataCRC.DataCRC = CRC16(Encoding_Data.DataBlock.Components.ClearText);    // Calculate CRC16


  // Put Data and CRC together
  Encoding_Data.DataBlock.Components.ClearText += (char)Encoding_Data.DataBlock.Components.DataCRC.LowerCRC_Byte;
  Encoding_Data.DataBlock.Components.ClearText += (char)Encoding_Data.DataBlock.Components.DataCRC.UpperCRC_Byte;


  // Encrypt if needed
  if (Encoding_Data.HeaderBlock.Components.Flag.Encrypted) {
    Encrypter.EncryptString(Encoding_Data.DataBlock.Components.ClearText, Encoding_Data.DataBlock.DataBlock_String, Encoding_Data.DataBlock.Components.ClearText.length());
  }
  else {
    Encoding_Data.DataBlock.DataBlock_String = Encoding_Data.DataBlock.Components.ClearText;
  }


  Encoding_Data.HeaderBlock.Components.DataBlockLength.DataBlockLength = Encoding_Data.DataBlock.DataBlock_String.length() + 32769;  // 32769 to avoid \0 bytes in Message String
}



bool MessageEncoder::destructDataBlock() {

  // check if real length matches length from header
  if (Decoding_Data.DataBlock.DataBlock_String.length() != Decoding_Data.HeaderBlock.Components.DataBlockLength.DataBlockLength - 32769) {  // 32769 to avoid \0 bytes in Message String
    return false;
  }


  // Decrypt if needed
  if (Decoding_Data.HeaderBlock.Components.Flag.Encrypted) {
    Encrypter.DecryptString(Decoding_Data.DataBlock.DataBlock_String, Decoding_Data.DataBlock.Components.ClearText, Decoding_Data.DataBlock.DataBlock_String.length());
  }
  else {
    Decoding_Data.DataBlock.Components.ClearText = Decoding_Data.DataBlock.DataBlock_String;
  }


  int lastIndex = Decoding_Data.DataBlock.Components.ClearText.length() - 1;

  Decoding_Data.DataBlock.Components.DataCRC.LowerCRC_Byte = Decoding_Data.DataBlock.Components.ClearText.charAt(lastIndex - 1);
  Decoding_Data.DataBlock.Components.DataCRC.UpperCRC_Byte = Decoding_Data.DataBlock.Components.ClearText.charAt(lastIndex);

  Decoding_Data.DataBlock.Components.ClearText.remove(lastIndex - 1);


  if (Decoding_Data.DataBlock.Components.DataCRC.DataCRC != CRC16(Decoding_Data.DataBlock.Components.ClearText)) {  // Check received CRC against calculated CRC
    return false;
  }


  return true;
}





byte MessageEncoder::findCharLocations(String& inp, char findIt, unsigned short (&resultList)[40]) {

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
  const int Char13Size = 40;
  unsigned short Char13Pos[Char13Size] = {};
  byte lastUsedArrayIndex = findCharLocations(Decoding_Data.CompleteMessage, char(13), Char13Pos);



  for (int i = 0;  i < Char13Size;  i++) {  // Surch for char(2) char(13) char(2) combination (before header)

    if (Decoding_Data.CompleteMessage.charAt(Char13Pos[i] - 1) == char(2)  and  Decoding_Data.CompleteMessage.charAt(Char13Pos[i] + 1) == char(2) ) {
      HeaderStartIndex = Char13Pos[i] + 2;
      HeaderEndIndex = Char13Pos[i] + 2 + _HeaderSize;
      DataStartIndex = Char13Pos[i] + 2 + _HeaderSize;
      break;
    }
  }

  
  for (int i = lastUsedArrayIndex;  i >= 0;  i--) {  // Surch for char(3) char(13) char(3) combination (after data)

    if (Decoding_Data.CompleteMessage.charAt(Char13Pos[i] - 1) == char(3)  and  Decoding_Data.CompleteMessage.charAt(Char13Pos[i] + 1) == char(3)) {
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
