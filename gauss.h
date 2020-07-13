#ifndef GAUSS_H_
#define GAUSS_H_

#include <set>
#include <utility>
#include <vector>

template <class T>
void scaleRow(std::vector<std::vector<T>>* matrix, int row, T value) {
  for (int j = 0; j < (*matrix)[row].size(); j++) {
    (*matrix)[row][j] *= value;
  }
}

template <class T>
void shearRow(std::vector<std::vector<T>>* matrix, int pivot_row, T value,
              int row) {
  for (int j = 0; j < (*matrix)[row].size(); j++) {
    (*matrix)[row][j] -= value * (*matrix)[pivot_row][j];
  }
}

template <class T>
void swapRows(std::vector<std::vector<T>>* matrix, int row1, int row2) {
  if (row1 == row2) {
    return;
  }
  std::swap((*matrix)[row1], (*matrix)[row2]);
}

template <class T>
std::pair<std::vector<T>, std::vector<std::vector<T>>> solve(
    const std::vector<std::vector<T>>& matrix, const std::vector<T>& rhs) {
  int rows = matrix.size();
  int cols = matrix[0].size();
  std::vector<std::vector<T>> m(rows, std::vector<T>(cols + 1));
  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < cols; j++) {
      m[i][j] = matrix[i][j];
    }
    m[i][cols] = rhs[i];
  }
  std::set<int> slips;
  int pivot_row = 0;
  int pivot_col = 0;
  while (pivot_row < rows) {
    if (pivot_col >= cols) {
      return std::make_pair(std::vector<T>(), std::vector<std::vector<T>>());
    }
    for (int i = pivot_row; i < rows; i++) {
      if (m[i][pivot_col] != 0) {
        swapRows(&m, pivot_row, i);
        break;
      }
    }
    if (m[pivot_row][pivot_col] == 0) {
      slips.insert(pivot_col);
      pivot_col++;
      continue;
    }
    scaleRow(&m, pivot_row, 1 / m[pivot_row][pivot_col]);
    for (int i = pivot_row + 1; i < rows; i++) {
      shearRow(&m, pivot_row, m[i][pivot_col], i);
    }
    pivot_row++;
    pivot_col++;
  }
  while (pivot_col < cols) {
    slips.insert(pivot_col);
    pivot_col++;
  }
  std::vector<T> result(cols);
  std::vector<std::vector<T>> hom;
  pivot_col = cols - 1;
  for (int pivot_row = rows - 1; pivot_row >= 0; pivot_row--) {
    while (slips.find(pivot_col) != slips.end()) {
      result[pivot_col] = 0;
      pivot_col--;
    }
    for (int i = pivot_row - 1; i >= 0; i--) {
      shearRow(&m, pivot_row, m[i][pivot_col], i);
    }
    result[pivot_col] = m[pivot_row][cols];
    pivot_col--;
  }
  pivot_col = cols - 1;
  for (int pivot_row = rows - 1; pivot_row >= 0; pivot_row--) {
    int last_col = pivot_col;
    while (slips.find(pivot_col) != slips.end()) {
      result[pivot_col] = 0;
      pivot_col--;
    }
    for (int j = last_col; j > pivot_col; j--) {
      std::vector<T> h(cols, 0);
      h[j] = 1;
      int col = pivot_col;
      for (int i = pivot_row; i >= 0; i--) {
        while (slips.find(col) != slips.end()) {
          col--;
        }
        h[col] -= m[i][j];
        col--;
      }
      hom.push_back(h);
    }
    pivot_col--;
  }
  return make_pair(result, hom);
}

#endif  // GAUSS_H_
