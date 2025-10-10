/// Utilities for collection data structures.
library;

//TODO: Consider using package:collections instead if more methods from the
// package become useful. For now probably not worth the expanded attack
// surface and an extra dependency.
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

extension ListDeletion on List {
  /// Overwrite elements with zeros so that the data is destroyed.
  ///
  /// Usually followed by setting all references of the `List` to `null` so it
  /// can later be deleted by the garbage collector. By overwriting the data
  /// first, the data is destroyed immediately rather than waiting for the next
  /// garbage collector cycle, and avoids the risk that a dangling reference
  /// keeps the `List` alive longer than expected. Thus overwriting is an extra
  /// security precaution.
  void overwriteWithZeros() {
    for (var i = 0; i < length; i++) {
      this[i] = 0;
    }
  }
}
