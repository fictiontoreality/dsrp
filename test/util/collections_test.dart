import 'package:dsrp/util/collections.dart';
import 'package:test/test.dart';

void main() {
  group('ListComparisons tests', () {
      group('shallowEquals tests', () {
        test('returns true for identical lists', () {
            final list1 = [1, 2, 3, 4, 5];
            final list2 = [1, 2, 3, 4, 5];
            expect(list1.shallowEquals(list2), true);
        });

        test('returns true for empty lists', () {
            final list1 = <int>[];
            final list2 = <int>[];
            expect(list1.shallowEquals(list2), true);
        });

        test('returns true for single element lists', () {
            final list1 = [42];
            final list2 = [42];
            expect(list1.shallowEquals(list2), true);
        });

        test('returns false for lists with different lengths', () {
            final list1 = [1, 2, 3];
            final list2 = [1, 2];
            expect(list1.shallowEquals(list2), false);
        });

        test('returns false for lists with different elements', () {
            final list1 = [1, 2, 3];
            final list2 = [1, 2, 4];
            expect(list1.shallowEquals(list2), false);
        });

        test('returns false for lists with same elements in different order', () {
            final list1 = [1, 2, 3];
            final list2 = [3, 2, 1];
            expect(list1.shallowEquals(list2), false);
        });

        test('works with string lists', () {
            final list1 = ['hello', 'world'];
            final list2 = ['hello', 'world'];
            final list3 = ['hello', 'dart'];
            expect(list1.shallowEquals(list2), true);
            expect(list1.shallowEquals(list3), false);
        });

        test('works with byte lists', () {
            final list1 = [0, 1, 2, 255];
            final list2 = [0, 1, 2, 255];
            final list3 = [0, 1, 2, 254];
            expect(list1.shallowEquals(list2), true);
            expect(list1.shallowEquals(list3), false);
        });

        test('works with BigInt lists', () {
            final list1 = [BigInt.from(1), BigInt.from(2), BigInt.from(3)];
            final list2 = [BigInt.from(1), BigInt.from(2), BigInt.from(3)];
            final list3 = [BigInt.from(1), BigInt.from(2), BigInt.from(4)];
            expect(list1.shallowEquals(list2), true);
            expect(list1.shallowEquals(list3), false);
        });

        test('handles large lists efficiently', () {
            final list1 = List.generate(10000, (index) => index);
            final list2 = List.generate(10000, (index) => index);
            final list3 = List.generate(10000, (index) => index + 1);

            expect(list1.shallowEquals(list2), true);
            expect(list1.shallowEquals(list3), false);
        });

        test('works with mixed type lists', () {
            final list1 = [1, 'hello', true];
            final list2 = [1, 'hello', true];
            final list3 = [1, 'hello', false];
            expect(list1.shallowEquals(list2), true);
            expect(list1.shallowEquals(list3), false);
        });

        test('compares reference equality when appropriate', () {
            final obj1 = Object();
            final obj2 = Object();
            final list1 = [obj1];
            final list2 = [obj1];
            final list3 = [obj2];

            expect(list1.shallowEquals(list2), true);
            expect(list1.shallowEquals(list3), false);
        });

        test('compares nested lists by reference not value', () {
            // Note: The equals extension does not perform deep comparison
            // It compares elements using ==, so nested structures compare by reference
            final innerList1 = [1, 2];
            final innerList2 = [3, 4];
            final innerList3 = [1, 2]; // Same values as innerList1 but different object

            final list1 = [innerList1, innerList2];
            final list2 = [innerList1, innerList2]; // Same references
            final list3 = [innerList3, innerList2]; // Different reference for first element

            expect(list1.shallowEquals(list2), true);
            expect(list1.shallowEquals(list3), false); // Different objects even though values match
        });

        test('handles null elements', () {
            final list1 = [1, null, 3];
            final list2 = [1, null, 3];
            final list3 = [1, 2, 3];

            expect(list1.shallowEquals(list2), true);
            expect(list1.shallowEquals(list3), false);
        });

        test('differentiates between empty list and single null element', () {
            final list1 = <int?>[];
            final list2 = [null];

            expect(list1.shallowEquals(list2), false);
        });
      });
  });

  group('ListDeletion tests', () {
      group('overwriteWithZeros tests', () {
          test('overwrites all data with zeros', () {
              var list = [1, 2, 3];
              list.overwriteWithZeros();
              expect(list, [0, 0, 0]);
          });

          test('overwrites empty list without error', () {
              var list = <int>[];
              list.overwriteWithZeros();
              expect(list, <int>[]);
          });

          test('overwrites single element list', () {
              var list = [42];
              list.overwriteWithZeros();
              expect(list, [0]);
          });

          test('overwrites large list', () {
              var list = List.filled(1000, 123);
              list.overwriteWithZeros();
              expect(list, List.filled(1000, 0));
              expect(list.every((element) => element == 0), true);
          });

          test('overwrites byte list (cryptographic use case)', () {
              var secretKey = [0xFF, 0xAA, 0x55, 0xBB, 0xCC, 0xDD];
              secretKey.overwriteWithZeros();
              expect(secretKey, [0, 0, 0, 0, 0, 0]);
          });

          test('overwrites negative numbers', () {
              var list = [-1, -100, -999];
              list.overwriteWithZeros();
              expect(list, [0, 0, 0]);
          });

          test('overwrites mixed positive and negative numbers', () {
              var list = [100, -50, 200, -75, 0, 42];
              list.overwriteWithZeros();
              expect(list, [0, 0, 0, 0, 0, 0]);
          });

          test('overwrites list with existing zeros', () {
              var list = [0, 1, 0, 2, 0];
              list.overwriteWithZeros();
              expect(list, [0, 0, 0, 0, 0]);
          });

          test('preserves list length', () {
              var list = [1, 2, 3, 4, 5];
              final originalLength = list.length;
              list.overwriteWithZeros();
              expect(list.length, originalLength);
          });

          test('works with dynamically typed list', () {
              var list = <dynamic>[1, 2.5, 3];
              list.overwriteWithZeros();
              expect(list, [0, 0, 0]);
          });

          test('modifies list in place', () {
              var list = [10, 20, 30];
              final listReference = list;
              list.overwriteWithZeros();

              // Verify the same list object was modified
              expect(identical(list, listReference), true);
              expect(listReference, [0, 0, 0]);
          });

          test('security use case: overwrites session key', () {
              // Simulate a session key that needs to be securely erased
              var sessionKey = [101, 63, 34, 246, 210, 134, 205, 205];

              // Use the key for authentication...
              final keyWasUsed = sessionKey.isNotEmpty;
              expect(keyWasUsed, true);

              // Then securely erase it
              sessionKey.overwriteWithZeros();

              // Verify all sensitive data is destroyed
              expect(sessionKey.every((byte) => byte == 0), true);
          });

          test('security use case: overwrites private key material', () {
              // Simulate private key bytes that need secure deletion
              var privateKeyBytes = List.generate(32, (i) => (i * 7 + 13) % 256);
              expect(privateKeyBytes.any((b) => b != 0), true);

              privateKeyBytes.overwriteWithZeros();

              expect(privateKeyBytes.every((b) => b == 0), true);
              expect(privateKeyBytes.length, 32);
          });
      });
  });
}
