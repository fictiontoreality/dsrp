/// Utilities for collection data structures.
library;

//TODO: Consider using package:collections instead.
extension ListComparisons on List {
  /// True if two lists contain the same elements in the same order.
  ///
  /// This is a shallow comparison. It compares elements using the == operator,
  /// and hence compares non-primitive types by reference rather than value.
  ///
  /// For example, two lists of lists with the same values may not be equal if
  /// the inner lists are not the same objects (hence differ by references).
  bool shallowEquals(List list) {
    if (length != list.length) return false;
    for (var i = 0; i < list.length; i++) {
      if (this[i] != list[i]) {
        return false;
      }
    }
    return true;
  }
}
