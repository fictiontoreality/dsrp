import 'package:dsrp/util/collections.dart';
import 'package:test/test.dart';

void main() {
  group('ListComparisons.equals tests', () {
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
}
