#pragma once

#include "StringEncryption.h"



typedef struct {
  uint8_t MessageID;
  bool Encrypt = false;
  bool needACK = false;
  bool isACK = false;
  String Data = "";
} encoding_inputs;


typedef struct {
  uint8_t NetworkID;
  uint8_t SenderID;
  uint8_t MessageID;
  bool wasEncrypted = false;
  bool needACK = false;
  bool isACK = false;
  String Data = "";
} decoding_outputs;





class MessageEncoder {
public:

/** @param NetworkID: ...
  * @param SenderID: ...
  * @param maxMessageSize: ...
  * @param EnctyptionKey: ...
  */
  void setEncoding (uint8_t NetworkID, uint8_t SenderID, uint16_t maxMessageSize, const uint8_t *EnctyptionKey);
  

/** @param Input: ...
  * @param Message: ...
  * @param return: ...
  */
  bool Encode(encoding_inputs* Input, String* Message);


/** @param Message: ...
  * @param Output: ...
  * @param return: ...
  */
  bool Decode(String* Message, decoding_outputs* Output);




private:

  #pragma region data_structure


  union flag_union {
    char Flag_Byte;

    struct {
      bool Encrypted : 1;
      bool needACK : 1;
      bool isACK : 1;
      bool Bit4 : 1;
      bool Bit5 : 1;
      bool Bit6 : 1;
      bool Bit7 : 1;
      bool Bit8 : 1;
    };
  };


  union datablock_length_union {
    uint16_t DataBlockLength;

    struct {
      uint8_t LowerDBL_Byte;
      uint8_t UpperDBL_Byte;
    };
  };


  union data_crc_union {
    uint16_t DataCRC;

    struct {
      uint8_t LowerCRC_Byte;
      uint8_t UpperCRC_Byte;
    };
  };



  struct header_components {
    uint8_t NetworkID;
    uint8_t SenderID;
    uint8_t MessageID;
    flag_union Flag;
    datablock_length_union DataBlockLength;
    uint8_t HeaderCRC;
  };


  struct header_block {
    header_components Components;
    String HeaderBlock_String;
  };



  struct data_components {
    String ClearText = "";   // currently saved last message
    data_crc_union DataCRC;
  };


  struct data_block {
    data_components Components;
    String DataBlock_String;
  };



  struct message_components {
    header_block HeaderBlock;
    data_block DataBlock;
    String CompleteMessage;
  };


  #pragma endregion data_structure
  


  message_components Encoding_Data;
  message_components Decoding_Data;


  StringEncryption_ChaCha Encrypter;
  uint8_t _NetworkID;
  uint8_t _SenderID;
  uint16_t _maxEncodedLength;


  void constructHeaderBlock();
  bool destructHeaderBlock(); // return crc ok

  uint8_t CRC8 (const String &input);


  void constructDataBlock();
  bool destructDataBlock();   // return crc ok

  uint16_t CRC16 (const String &input);


  bool splitMessage();
  byte findCharLocations(String& inp, char findIt, unsigned short (&resultList)[40]);
};
