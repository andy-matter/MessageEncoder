
#include <Arduino.h>
#include <MessageEncoder.h>


byte Key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};;
MessageEncoder MsgEnc;
MessageEncoder MsgDec;

MessageEncoder::enc_in Enc_Input;
MessageEncoder::dec_out Dec_Output;

String Payload = "This is a test-payload, here are some character for testing: Test123!§$%/*_#;)";
String Message;




void setup() {
  MsgEnc.setEncoding(2, 25, 1000, Key);   // Setting up En-/Decoder according to the described parameters
  MsgDec.setEncoding(2, 69, 1000, Key);

  Serial.begin(115200);
  delay(2500);
}




void loop() {

  // Writing settings and payload to the encoder-input
  Enc_Input.ReceiverID = 0;   // Receiver ID 0 is Broadcast to all devices in the Network
  Enc_Input.MessageID = 45;   // e.g. for identification of payload
  Enc_Input.needACK = true;
  Enc_Input.isACK = false;
  Enc_Input.Encrypt = true;
  Enc_Input.Data = Payload;


  MsgEnc.Encode(&Enc_Input, &Message);    // Encode to String

  Serial.println(Message);

  MsgDec.Decode(&Message, &Dec_Output);   // Decode the String


  if (!Enc_Input.Data.equals(Dec_Output.Data)) {    // Compare the data before and after encoding/decoding
    Serial.println(Enc_Input.Data);
    Serial.println(Dec_Output.Data);
    Serial.println("Test Failed!");
  }

  while(1);   // Freeze the loop
}