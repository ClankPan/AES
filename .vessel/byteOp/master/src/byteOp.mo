import Int32 "mo:base/Int32";
import Nat32 "mo:base/Nat32";
import Nat8 "mo:base/Nat8";
import Array "mo:base/Array";

import Debug "mo:base/Debug";
import Prim "mo:⛔";


module {

  public func slice1Byte_toLitleEndian(int32 : Int32) : [Nat8] {
    // Int32->Int->Nat8
    // Int32 >> n ->Int->Int8->Nat8
    let nat8_1 : Nat8 = Prim.intToNat8Wrap(Int32.toInt((int32 >> 24) & 0xFF));
    let nat8_2 : Nat8 = Prim.intToNat8Wrap(Int32.toInt((int32 >> 16) & 0xFF));
    let nat8_3 : Nat8 = Prim.intToNat8Wrap(Int32.toInt((int32 >>  8) & 0xFF));
    let nat8_4 : Nat8 = Prim.intToNat8Wrap(Int32.toInt((int32 >>  0) & 0xFF));

    // litle Endian
    [nat8_4, nat8_3, nat8_2, nat8_1]
  };

  public func cat4Byte_fromLitleEndian(nat8Array : [Nat8]) : Int32 {
    // Nat8->Nat->Nat32->Int32
    let a = Int32.fromNat32(Nat32.fromNat((Nat8.toNat(nat8Array[3]))) << 24); 
    let b = Int32.fromNat32(Nat32.fromNat((Nat8.toNat(nat8Array[2]))) << 16); 
    let c = Int32.fromNat32(Nat32.fromNat((Nat8.toNat(nat8Array[1]))) <<  8); 
    let d = Int32.fromNat32(Nat32.fromNat((Nat8.toNat(nat8Array[0]))) <<  0); 

    a | b | c | d
  };

  public func to1ByteBase(int32Array : [Int32]) : [Nat8] {
    // [Int32,...]->[Nat8,Nat8,Nat8,Nat8,...]
    Array.flatten<Nat8>(
      Array.map<Int32,[Nat8]>(int32Array, slice1Byte_toLitleEndian)
    );
  };

  public func to4ByteBase(nat8Array : [Nat8]) : [Int32] {
    // 4個ごとに折り畳んで、それらをNat32にする
    Array.map<[Nat8], Int32>(fold4Nat8Array(nat8Array), cat4Byte_fromLitleEndian);
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

  public func byteCopy(to : [Nat8], from : [Nat8], n : Nat) : [Nat8] {
    Array.mapEntries<Nat8, Nat8>(to, func(v, i){
      if (i < n) from[i]
      else v
    })
  };

  // // /************************************************************/
  // // /* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
  // public func RotWord(_in :  Int32) : Int32 {
  //   let cin  : [Nat8] = slice1Byte_toLitleEndian(_in);
  //   let cin2 : [Nat8] = [cin[1], cin[2], cin[3], cin[0]];

  //   Debug.print("cin2 " # debug_show([cin2[0], cin2[1], cin2[2], cin2[3]]));

  //   cat4Byte_fromLitleEndian(cin2)
  // };







  // func to1ByteBase(nat32Array : [Nat32]) : [Nat8] {
  //   // [Nat32,...]->[Nat8,Nat8,Nat8,Nat8,...]
  //   Array.flatten<Nat8>(
  //     Array.map<Nat32,[Nat8]>(nat32Array, Nat32ToNat8Array)
  //   );
  //   // Array.flatten<Nat8>(Array.map<Nat32, [Nat8]>(nat32Array, func(nat32){
  //   //   Array.map<Nat8, Nat8>(Nat32ToNat8Array(nat32), func(val){
  //   //       Sbox[Nat8.toNat(val)]// return Nat8
  //   //     });
  //   //   }));
  // };
  // func to4ByteBase(nat8Array : [Nat8]) : [Nat32] {
  //   // 4個ごとに折り畳んで、それらをNat32にする
  //   Array.map<[Nat8], Nat32>(fold4Nat8Array(nat8Array), Nat8ArrayToNat32);
  // };


  // /*
  // // nat8->int8
  // let nat8 : Nat8 = 0xFF;
  // let int8 : Int8 = Prim.nat8ToInt8(nat8);
  // Debug.print(debug_show(nat8, int8));
  // // -> (255, -1)

  // 符号bitも保たれている．

  // intToInt8がある．

  // */


  // func Nat32ToNat8Array(nat32 : Nat32) : [Nat8] {

  //   let a : Nat8 = Nat8.fromNat( Nat32.toNat((nat32 >> 24) & 0xFF));
  //   let b : Nat8 = Nat8.fromNat( Nat32.toNat((nat32 >> 16) & 0xFF));
  //   let c : Nat8 = Nat8.fromNat( Nat32.toNat((nat32 >>  8) & 0xFF));
  //   let d : Nat8 = Nat8.fromNat( Nat32.toNat((nat32 >>  0) & 0xFF));
  //   [a,b,c,d]
  // };
  // func Nat8ArrayToNat32(nat8Array : [Nat8]) : Nat32 {
  //   // Nat8->Nat->Nat32->Int32
  //   let a = Nat32.fromNat((Nat8.toNat(nat8Array[0]))) << 24; 
  //   let b = Nat32.fromNat((Nat8.toNat(nat8Array[1]))) << 16; 
  //   let c = Nat32.fromNat((Nat8.toNat(nat8Array[2]))) <<  8; 
  //   let d = Nat32.fromNat((Nat8.toNat(nat8Array[3]))) <<  0; 
  //   a | b | c | d
  // };


  // func flattenNat8ArrayArray(nat8ArrayArray : [[Nat8]]) : [Nat8] {
  //   Array.flatten(nat8ArrayArray);
  // };
  // func fold4Nat8Array(nat8Array : [Nat8]) : [[Nat8]] {
  //   var i = 0;
  //   Array.mapFilter<Nat8,[Nat8]>(nat8Array, func(_) : ?[Nat8] {
  //     let op = if (i%4 == 0) ?[nat8Array[i],nat8Array[i+1],nat8Array[i+2],nat8Array[i+3]]
  //     else null;
  //     i += 1;
  //     op
  //   });
  // };
}