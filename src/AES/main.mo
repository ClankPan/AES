


import Array "mo:base/Array";
import Debug "mo:base/Debug";
import Iter "mo:base/Iter";
import Int32 "mo:base/Int32";
import Nat32 "mo:base/Nat32";
import Nat8 "mo:base/Nat8";
import Blob "mo:base/Blob";
import Text "mo:base/Text";

actor {
  /************************************************************/
  let NB : Nat = 4;
  let NBb : Nat = 16;
  var key : [var Nat8] = Array.init<Nat8>(32, 0x00); // Nat8 == unsinged char
  var w : [var Nat32] = Array.init<Nat32>(60, 0);
  var data : [Nat32] = Array.freeze(Array.init<Nat32>(NB, 0));
  var nk : Nat32 = 0; /* 4,6,8(128,192,256 bit) 鍵の長さ */
  var nr : Nat32 = 0; /* 10,12,14 ラウンド数 */

  /************************************************************/

  func datadump(c : Text, dt : [Nat32], len : Nat) {
    let cdt = to1ByteBase(dt);
    let blob = Blob.fromArray(cdt);
    // Debug.print(debug_show(Text.decodeUtf8(blob)));
    Debug.print(c # debug_show(cdt));
  };

  public func test() {
    Debug.print("\n\n\n---------------------------------");
    let keys : [Nat8] = 
      [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
      0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
      0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
      0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f];
    
    let init : [Nat8] = 
      [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
      0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff];

    var key : [Nat8] = sliceArray<Nat8>(keys, 16);
    
    nk := 4;              //鍵の長さ 4,6,8(128,192,256 bit)
    nr := nk + 6;          //ラウンド数 10,12,14

    // Debug.print("SubWork" # debug_show([SubWord(0), SubWord(1), SubWord(2)]));
    // Debug.print("RotWord" # debug_show([RotWord(10), RotWord(100), RotWord(200)]));

    KeyExpansion(key); //暗号化するための鍵の準備
    data := to4ByteBase(sliceArray<Nat8>(init, NBb));

    datadump("w : ", Array.freeze(w),4);

    Debug.print("  <FIPS 197  P.35 Appendix C.1 AES-128 TEST>\n\n");
    datadump("PLAINTEXT: ",data,4);
    datadump("KEY:       ",to4ByteBase(key),4);
    data := Cipher(data);
    datadump("暗号化:    ",data,4);
    data := invCipher(data);
    datadump("復号化:    ",data,4);
  };

  // public func test() {
  //   let keys : [Nat8] = 
  //     [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
  //     0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
  //     0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
  //     0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f];
    
  //   let init : [Nat8] = 
  //     [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
  //     0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff];

  //   var key : [Nat8] = sliceArray<Nat8>(keys, 16);
    
  //   nk := 4;              //鍵の長さ 4,6,8(128,192,256 bit)
  //   nr := nk + 6;          //ラウンド数 10,12,14

  //   KeyExpansion(key); //暗号化するための鍵の準備
  //   data := to4ByteBase(sliceArray<Nat8>(init, NBb));

  //   datadump("w : ", Array.freeze(w),4);

  //   Debug.print("  <FIPS 197  P.35 Appendix C.1 AES-128 TEST>\n\n");
  //   datadump("PLAINTEXT: ",data,4);
  //   datadump("KEY:       ",to4ByteBase(key),4);
  //   data := Cipher(data);
  //   datadump("暗号化:    ",data,4);
  // };

  /************************************************************/
  /* FIPS 197  P.16 Figure 7 */
  let Sbox : [Nat8] = [ //Int32からNat8へ変更した。0xFFは1byte
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
  ];

  /************************************************************/
  /* FIPS 197  P.22 Figure 14 */
  let invSbox : [Nat8] = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
  ];

  /************************************************************/
/* FIPS 197  P.15 Figure 5 */ //暗号化
  func Cipher(_data : [Nat32]) : [Nat32] {

    var data : [Nat32] = _data;
    data := AddRoundKey(data,0);

    // datadump("暗号化 step1:    ",data,4);

    var i : Nat32 = 1;
    while(i < nr) {
      data := SubBytes(data);
      data := ShiftRows(data);
      data := MixColumns(data);
      data := AddRoundKey(data,Nat32.toNat(i));

      i +=1;
    };

    data := SubBytes(data);
    data := ShiftRows(data);
    data := AddRoundKey(data,Nat32.toNat(i));
    return data;
  };

  /************************************************************/
  /* FIPS 197  P.21 Figure 12 */ //復号化
  func invCipher(_data : [Nat32]) : [Nat32] {

    var data : [Nat32] = _data;
    data := AddRoundKey(data,0);

    // datadump("暗号化 step1:    ",data,4);

    var i : Nat32 = nr-1;
    while(i > 0) {
      data := invShiftRows(data);
      data := invSubBytes(data);
      data := AddRoundKey(data,Nat32.toNat(i));
      data := invMixColumns(data);

      i -=1;
    };

    data := invShiftRows(data);
    data := invSubBytes(data);
    data := AddRoundKey(data,Nat32.toNat(i));
    return data;
  };


  /************************************************************/
  /* FIPS 197  P.19 Figure 10 */
  // 1byteごとの配列を4byteごと配列に変換しておく
  func AddRoundKey(data : [Nat32], n : Nat) : [Nat32] { //　w[i+NB*n]の型推論のためnはNatとする
    // int i;
    // for(i=0;i<NB;i++)
    // {
    //   data[i] ^= w[i+NB*n];
    // }
    Array.mapEntries<Nat32, Nat32>(data, func(_, i){w[i+NB*n]});
  };

  /************************************************************/
  /* FIPS 197  P.16 Figure 6 */
  func SubBytes(data :[Nat32]) : [Nat32] {
    // unsigned char *cb=(unsigned char*)data; // 4byteのint32を1byteごとにアクセスできるようにしている
    // for(i=0;i<NBb;i+=4)//理論的な意味から二重ループにしているが意味は無い
    // {
    //   for(j=0;j<4;j++)
    //   {
    //     cb[i+j] = Sbox[cb[i+j]];
    //   }
    // }

    // apply Sbox
    let sboxedData = Array.map<Nat8, Nat8>(to1ByteBase(data), func (val) {Sbox[Nat8.toNat(val)]});
    to4ByteBase(sboxedData);

    // // [Nat32,...]->[[Nat8,Nat8,Nat8,Nat8],...]
    // var nat8Array : [[Nat8]] = Array.map<Nat32, [Nat8]>(data, 
    //   func(nat32){
    //     Array.map<Nat8, Nat8>(Nat32ToNat8Array(nat32), 
    //       func(val){
    //         Sbox[Nat8.toNat(val)]// return Nat8
    //       });
    //   });
    // // [[Nat8,Nat8,Nat8,Nat8],...]->[Nat32,...]
    // Array.map<[Nat8], Nat32>(nat8Array, Nat8ArrayToNat32);
  };


  /************************************************************/
  /* FIPS 197  P.22 5.3.2 */
  func invSubBytes(data :[Nat32]) : [Nat32] {
    // apply Sbox
    let sboxedData = Array.map<Nat8, Nat8>(to1ByteBase(data), func (val) {invSbox[Nat8.toNat(val)]});
    to4ByteBase(sboxedData);
  };


  /************************************************************/
  /* FIPS 197  P.17 Figure 8 */
  func ShiftRows(data :[Nat32]) : [Nat32] {
    // int i,j,i4;
    // unsigned char *cb=(unsigned char*)data;
    // unsigned char cw[NBb];
    // memcpy(cw,cb,sizeof(cw));
    // for(i=0;i<NB;i+=4)
    // {
    //   i4 = i*4;
    //   for(j=1;j<4;j++)
    //   {
    //     cw[i4+j+0*4] = cb[i4+j+((j+0)&3)*4];
    //     cw[i4+j+1*4] = cb[i4+j+((j+1)&3)*4];
    //     cw[i4+j+2*4] = cb[i4+j+((j+2)&3)*4];
    //     cw[i4+j+3*4] = cb[i4+j+((j+3)&3)*4];
    //   }
    // }
    // memcpy(cb,cw,sizeof(cw));

    let cb : [Nat8] = to1ByteBase(data);
    var cw : [var Nat8] = Array.thaw<Nat8>(sliceArray<Nat8>(cb, NBb)); // NBb(16)個分のNat8を切り出す．

    var i = 0;
    while (i < NB) {
      let i4 = i*4;
      var j = 1;
      while (j < 4) {
        // &などのbit opはNat型には許可されてないので，Nat32へキャスト
        cw[i4+j+0*4] := cb[i4+j+Nat32.toNat((Nat32.fromNat((j+0))&3))*4];
        cw[i4+j+1*4] := cb[i4+j+Nat32.toNat((Nat32.fromNat((j+1))&3))*4];
        cw[i4+j+2*4] := cb[i4+j+Nat32.toNat((Nat32.fromNat((j+2))&3))*4];
        cw[i4+j+3*4] := cb[i4+j+Nat32.toNat((Nat32.fromNat((j+3))&3))*4];

        j +=1;
      };

      i +=4;
    };

    // memcpy(cb,cw,sizeof(cw));
    let nat8Array = Array.mapEntries<Nat8, Nat8>(cb, func(v, i) {
      if (i < NBb) cw[i]
      else v
    });
    
    to4ByteBase(nat8Array)
  };

  /************************************************************/
  /* FIPS 197  P.22 Figure 13 */ 
  func invShiftRows(data :[Nat32]) : [Nat32] {

    let cb : [Nat8] = to1ByteBase(data);
    var cw : [var Nat8] = Array.thaw<Nat8>(sliceArray<Nat8>(cb, NBb)); // NBb(16)個分のNat8を切り出す．

    var i = 0;
    while (i < NB) {
      let i4 = i*4;
      var j = 1;
      while (j < 4) {
        // &などのbit opはNat型には許可されてないので，Nat32へキャスト
        cw[i4+j+Nat32.toNat((Nat32.fromNat((j+0))&3))*4] := cb[i4+j+0*4];
        cw[i4+j+Nat32.toNat((Nat32.fromNat((j+1))&3))*4] := cb[i4+j+1*4];
        cw[i4+j+Nat32.toNat((Nat32.fromNat((j+2))&3))*4] := cb[i4+j+2*4];
        cw[i4+j+Nat32.toNat((Nat32.fromNat((j+3))&3))*4] := cb[i4+j+3*4];

        j +=1;
      };

      i +=4;
    };

    let nat8Array = Array.mapEntries<Nat8, Nat8>(cb, func(v, i) {
      if (i < NBb) cw[i]
      else v
    });
    
    to4ByteBase(nat8Array)
  };


  /************************************************************/
  /* FIPS 197 P.10 4.2 乗算 (n倍) */
  func mul(dt : Nat32, n : Nat32) : Nat32 {
    var i : Nat32 = 8;
    var x : Nat32 = 0;
    while (i > 0) {
      x <<= 1;
      if(x&0x100 != 0) x := (x ^ 0x1b) & 0xff;
      if((n & i) != 0) x ^= dt;

      i >>= 1;
    };
    x

    // for(i=8;i>0;i>>=1)
    // {
    //   x <<= 1;
    //   if(x&0x100)
    //     x = (x ^ 0x1b) & 0xff;
    //   if((n & i))
    //     x ^= dt;
    // }
    // return(x);
  };

  /************************************************************/
  func dataget(data : [Nat32], n : Nat) : Nat32 {
    // [Nat32]->[Nat8]->Nat8->Nat->Nat32
    Nat32.fromNat(Nat8.toNat(to1ByteBase(data)[n]))
    /*
    (unsigned char*)data // void* のdataをusingedへキャスト　これはポインタ型なので，配列本体へは影響を及ぼさない
    そこから[]演算子でn番目を参照する．1byteのデータだが，それは4byteのint型として暗黙でキャストされる
    */
  };
  /************************************************************/
  /* FIPS 197  P.18 Figure 9 */
  func MixColumns(data : [Nat32]) : [Nat32] {
    var nat32Array : [var Nat32] = Array.init<Nat32>(NB, 0);
    var i = 0;
    while (i < NB) {
      let i4 = i*4;

      var x = 
            mul(dataget(data,i4+0),2) ^
            mul(dataget(data,i4+1),3) ^
            mul(dataget(data,i4+2),1) ^
            mul(dataget(data,i4+3),1);

      x |= (mul(dataget(data,i4+1),2) ^
            mul(dataget(data,i4+2),3) ^
            mul(dataget(data,i4+3),1) ^
            mul(dataget(data,i4+0),1)) << 8;

      x |= (mul(dataget(data,i4+2),2) ^
            mul(dataget(data,i4+3),3) ^
            mul(dataget(data,i4+0),1) ^
            mul(dataget(data,i4+1),1)) << 16;

      x |= (mul(dataget(data,i4+3),2) ^
            mul(dataget(data,i4+0),3) ^
            mul(dataget(data,i4+1),1) ^
            mul(dataget(data,i4+2),1)) << 24;

     nat32Array[i] := x;

      i +=1;
    };

    Array.freeze<Nat32>(nat32Array);

    // for(i=0;i<NB;i++)
    // {
    //   i4 = i*4;
    //   x  =  mul(dataget(data,i4+0),2) ^
    //         mul(dataget(data,i4+1),3) ^
    //         mul(dataget(data,i4+2),1) ^
    //         mul(dataget(data,i4+3),1);
    //   x |= (mul(dataget(data,i4+1),2) ^
    //         mul(dataget(data,i4+2),3) ^
    //         mul(dataget(data,i4+3),1) ^
    //         mul(dataget(data,i4+0),1)) << 8;
    //   x |= (mul(dataget(data,i4+2),2) ^
    //         mul(dataget(data,i4+3),3) ^
    //         mul(dataget(data,i4+0),1) ^
    //         mul(dataget(data,i4+1),1)) << 16;
    //   x |= (mul(dataget(data,i4+3),2) ^
    //         mul(dataget(data,i4+0),3) ^
    //         mul(dataget(data,i4+1),1) ^
    //         mul(dataget(data,i4+2),1)) << 24;
    //   data[i] = x;
    // } 
  };

  /************************************************************/
  /* FIPS 197  P.23 5.3.3 */
  func invMixColumns(data : [Nat32]) : [Nat32] {
    var nat32Array : [var Nat32] = Array.init<Nat32>(NB, 0);
    var i = 0;
    while (i < NB) {
      let i4 = i*4;

      var x  =  mul(dataget(data,i4+0),14) ^
            mul(dataget(data,i4+1),11) ^
            mul(dataget(data,i4+2),13) ^
            mul(dataget(data,i4+3), 9);

      x |= (mul(dataget(data,i4+1),14) ^
            mul(dataget(data,i4+2),11) ^
            mul(dataget(data,i4+3),13) ^
            mul(dataget(data,i4+0), 9)) << 8;

      x |= (mul(dataget(data,i4+2),14) ^
            mul(dataget(data,i4+3),11) ^
            mul(dataget(data,i4+0),13) ^
            mul(dataget(data,i4+1), 9)) << 16;

      x |= (mul(dataget(data,i4+3),14) ^
            mul(dataget(data,i4+0),11) ^
            mul(dataget(data,i4+1),13) ^
            mul(dataget(data,i4+2), 9)) << 24;

     nat32Array[i] := x;

      i +=1;
    };

    Array.freeze<Nat32>(nat32Array);

  };

  /************************************************************/
  /* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
  func SubWord(_in : Nat32) : Nat32 {
    let cin : [Nat8] = Nat32ToNat8Array(_in);
    // let nat8Array = Array.map<Nat8, Nat8>(cin, func(v){Sbox[Nat8.toNat(v)]});
    let nat8Array : [Nat8] = [
                              Sbox[Nat8.toNat(cin[0])],
                              Sbox[Nat8.toNat(cin[1])],
                              Sbox[Nat8.toNat(cin[2])],
                              Sbox[Nat8.toNat(cin[3])]
                             ];

    Nat8ArrayToNat32(nat8Array)
  };

  /************************************************************/
  /* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
  func RotWord(_in : Nat32) : Nat32 {
    let cin  : [Nat8] = Nat32ToNat8Array(_in);
    let cin2 : [Nat8] = [cin[1], cin[2], cin[3], cin[0]];

    Nat8ArrayToNat32(cin2)
  };

  /************************************************************/
  /* FIPS 197  P.20 Figure 11 */
  func KeyExpansion(key : [Nat8]) {

    // Natへのキャスト
    let _nk = Nat32.toNat(nk);
    let _nr = Nat32.toNat(nr);

    /* FIPS 197  P.27 Appendix A.1 Rcon[i/Nk] */ //又は mulを使用する
    let Rcon : [Nat32]= [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

    // w := Array.thaw(to4ByteBase( sliceArray<Nat8>(key, Nat32.toNat(nk*4))));
    w := Array.thaw(to4ByteBase( byteCopy(to1ByteBase(Array.freeze(w)), key, _nk*4)));

    var i = _nk;
    while (i < NB*(_nr+1)) {
      var temp : Nat32 = w[i-1];
      if((i%_nk) == 0) 
        temp := SubWord(RotWord(temp)) ^ Rcon[(i/_nk)-1]
      else if (_nk > 6 and (i%_nk) == 4)
        temp := SubWord(temp);
      
      w[i] := w[i-_nk] ^ temp;

      i +=1;
    };


    // for(i=nk;i<NB*(nr+1);i++)
    // {
    //   temp = w[i-1];
    //   if((i%nk) == 0)
    //     temp = SubWord(RotWord(temp)) ^ Rcon[(i/nk)-1];
    //   else if(nk > 6 && (i%nk) == 4)
    //     temp = SubWord(temp);
    //   w[i] = w[i-nk] ^ temp;
    // }
  };





  /************************************************************/ 
  func byteCopy(to : [Nat8], from : [Nat8], n : Nat) : [Nat8] {
    Array.mapEntries<Nat8, Nat8>(to, func(v, i){
      if (i < n) from[i]
      else v
    })
  };
  //先頭からn個までを切り出す
  func sliceArray<T>(array : [T], n : Nat) : [T] {
    var i = 0;
    Array.mapFilter<T, T>(array, func(_) {
      let op = if (i < n) ?array[i]
      else null;
      i += 1;
      op
    })
  };
  func to1ByteBase(nat32Array : [Nat32]) : [Nat8] {
    // [Nat32,...]->[Nat8,Nat8,Nat8,Nat8,...]
    Array.flatten<Nat8>(
      Array.map<Nat32,[Nat8]>(nat32Array, Nat32ToNat8Array)
    );
    // Array.flatten<Nat8>(Array.map<Nat32, [Nat8]>(nat32Array, func(nat32){
    //   Array.map<Nat8, Nat8>(Nat32ToNat8Array(nat32), func(val){
    //       Sbox[Nat8.toNat(val)]// return Nat8
    //     });
    //   }));
  };
  func to4ByteBase(nat8Array : [Nat8]) : [Nat32] {
    // 4個ごとに折り畳んで、それらをNat32にする
    Array.map<[Nat8], Nat32>(fold4Nat8Array(nat8Array), Nat8ArrayToNat32);
  };
  func Nat32ToNat8Array(nat32 : Nat32) : [Nat8] {
    let a : Nat8 = Nat8.fromNat( Nat32.toNat((nat32 >> 24) & 0xFF));
    let b : Nat8 = Nat8.fromNat( Nat32.toNat((nat32 >> 16) & 0xFF));
    let c : Nat8 = Nat8.fromNat( Nat32.toNat((nat32 >>  8) & 0xFF));
    let d : Nat8 = Nat8.fromNat( Nat32.toNat((nat32 >>  0) & 0xFF));
    [a,b,c,d]
  };
  func Nat8ArrayToNat32(nat8Array : [Nat8]) : Nat32 {
    // Nat8->Nat->Nat32
    let a = Nat32.fromNat((Nat8.toNat(nat8Array[0]))) << 24; 
    let b = Nat32.fromNat((Nat8.toNat(nat8Array[1]))) << 16; 
    let c = Nat32.fromNat((Nat8.toNat(nat8Array[2]))) <<  8; 
    let d = Nat32.fromNat((Nat8.toNat(nat8Array[3]))) <<  0; 
    a | b | c | d
  };
  func flattenNat8ArrayArray(nat8ArrayArray : [[Nat8]]) : [Nat8] {
    Array.flatten(nat8ArrayArray);
  };
  func fold4Nat8Array(nat8Array : [Nat8]) : [[Nat8]] {
    var i = 0;
    Array.mapFilter<Nat8,[Nat8]>(nat8Array, func(_) : ?[Nat8] {
      let op = if (i%4 == 0) ?[nat8Array[i],nat8Array[i+1],nat8Array[i+2],nat8Array[i+3]]
      else null;
      i += 1;
      op
    });
  };


};


/*
data [Int32] size 16 には、init(usinged char)が16個分入っている
unsigned char *cb=(unsigned char*)data; で　unsigned charにキャストする

1バイトのcharを、int32の配列に変換して、それを1byteで解釈する

4byteのInt32を　1byteのNat32 x 4に解釈する方法。

Int32%(256^4), Int32%(256^3), Int32%(256^2), Int32%(256^1)

10,000,000,000

リトルエンディアンと符号付きの話、

Int32ではなく、Nat32の方がいいかも。usinged charをmemcopyしているから、実質Nat8の配列と同じ。

ということは、初めからNat8で型をとった方がいい。

[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 215, 170, 116, 252, 211, 175, 114, 251, 219, 166, 120, 240, 215, 171, 118, 255, 181, 146, 98, 240, 102, 61, 16, 11, 189, 155, 104, 251, 106, 48, 30, 4, 177, 224, 144, 246, 215, 221, 128, 253, 106, 70, 232, 6, 0, 118, 246, 2, 137, 162, 231, 157, 94, 127, 103, 96, 52, 57, 143, 102, 52, 79, 121, 100, 13, 20, 164, 149, 83, 107, 195, 245, 103, 82, 76, 147, 83, 29, 53, 247, 169, 130, 204, 88, 250, 233, 15, 173, 157, 187, 67, 62, 206, 166, 118, 201, 141, 186, 17, 147, 119, 83, 30, 62, 234, 232, 93, 0, 36, 78, 43, 201, 162, 75, 204, 37, 213, 24, 210, 27, 63, 240, 143, 27, 27, 190, 164, 210, 12, 2, 121, 145, 217, 26, 171, 138, 230, 234, 36, 145, 253, 84, 128, 67, 44, 207, 99, 243, 245, 213, 200, 121, 19, 63, 236, 232, 238, 107, 108, 171, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

*/




