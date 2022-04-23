import utls "./utls/byteOp";
import Iter "mo:base/Iter";
import Int32 "mo:base/Int32";
import Nat32 "mo:base/Nat32";
import Nat8 "mo:base/Nat8";
import Prim "mo:⛔";
import Debug "mo:base/Debug";
import Array "mo:base/Array";

actor {
  // // Int32の範囲を全てチェック
  // let min : Nat = 0x00000000;
  // let max : Nat = 0xFFFFFFFF;
  // for (nat in Iter.range(min, max)) {
  //   //nat -> nat32 -> int32
  //   let int32 = Prim.nat32ToInt32(Nat32.fromNat(nat));

  //   let nat8Array = utls.slice1Byte_toLitleEndian(int32);
  //   let decoded_int32 = utls.cat4Byte_fromLitleEndian(nat8Array);

  //   if (int32 != decoded_int32) assert(false);
  // };

  var cw : [Nat8] = Array.tabulate<Nat8>(16, func(_){0});


}