import 'package:dsrp/util.dart';
import 'package:test/test.dart';

void main() {
  const bigByteList = [38, 173, 182, 68, 210, 122, 188, 207, 48, 253, 137, 75, 207, 161, 251, 108, 245, 255, 167, 202, 206, 107, 158, 251, 195, 6, 65, 137, 17, 179, 102, 100, 132, 48, 113, 113, 254, 245, 45, 219, 237, 31, 6, 151, 191, 168, 83, 66, 207, 8, 199, 134, 190, 75, 220, 9, 64, 121, 240, 52, 222, 188, 154, 105, 197, 164, 250, 30, 23, 49, 82, 177, 226, 142, 206, 13, 62, 99, 124, 227, 216, 71, 207, 125, 238, 243, 140, 229, 240, 97, 59, 147, 196, 207, 25, 45, 131, 40, 142, 179, 207, 120, 248, 12, 44, 30, 132, 18, 146, 181, 40, 228, 93, 61, 150, 122, 135, 109, 223, 183, 117, 30, 161, 177, 76, 29, 39, 62];
  const bigIntString = '27161010228836201331794825814212254193412576883239767951010568973113419272749595606994713559795908054476552975892723087928625289263682048688813889302265953405632407054280819018447028773187430846708335340490516628767589465122742382585417552365747410579614567450681640564993422830344268086482846053665685186366';
  final bigInt = BigInt.parse(bigIntString);

  group('convertByteListToBigInt tests', () {
      test('convertByteListToBigInt can convert large byte list', () {
          final bigInt = convertByteListToBigInt(bigByteList);
          expect(bigInt.toString(), bigIntString);
      });
  });

  group('convertBigIntToByteList tests', () {
      test('convertBigIntToByteList can convert large int', () {
          final byteList = convertBigIntToByteList(bigInt);
          expect(byteList, bigByteList);
      });
  });
}
