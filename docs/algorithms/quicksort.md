# 785. 快速排序

- [  题目](https://www.acwing.com/problem/content/description/787/)
- [  提交记录](https://www.acwing.com/problem/content/submission/787/)
- [  讨论](https://www.acwing.com/problem/content/discussion/index/787/1/)
- [  题解](https://www.acwing.com/problem/content/solution/787/1/)
- [  视频讲解](https://www.acwing.com/problem/content/video/787/)



给定你一个长度为n的整数数列。

请你使用快速排序对这个数列按照从小到大进行排序。

并将排好序的数列按顺序输出。

#### 输入格式

输入共两行，第一行包含整数 n。

第二行包含 n 个整数（所有整数均在1~109109范围内），表示整个数列。

#### 输出格式

输出共一行，包含 n 个整数，表示排好序的数列。

#### 数据范围

1≤n≤1000001≤n≤100000

#### 输入样例：

```
5
3 1 2 4 5
```

#### 输出样例：

```
1 2 3 4 5
```



```c++
#include <iostream>
using namespace std;

const int N = 100010;
int nums[N];
int n;

int partition(int *nums, int l, int r)
{
    int i = l-1, j = r+1, x = nums[(l+r) >> 1];
    while (i < j) {
        do { i++; } while (nums[i] < x);
        do { j--; } while (nums[j] > x);
        if (i < j) {
            swap(nums[i], nums[j]);
        }
    }
    
    return j;
}

void quick_sort(int *nums, int l, int r)
{
    if (l >= r) {
        return;
    }
    
    int p = partition(nums, l, r);
    quick_sort(nums, l, p);
    quick_sort(nums, p+1, r);
}

int main()
{
    scanf("%d", &n);
    for (int i = 0; i < n; i++) {
        scanf("%d", &nums[i]);
    }
    
    quick_sort(nums, 0, n-1);
    
    for (int i = 0; i < n; i++) {
        printf("%d ", nums[i]);
    }
    return 0;
}
```



## 2020-11-22 复习

```c++
#include <iostream>
#include <vector>
using namespace std;

int partition(vector<int> &nums, int left, int right)
{
    int v = nums[(left+right) >> 1];
    int i = left-1, j = right+1;
    
    while (i < j) {
        while (nums[++i] < v);
        while (nums[--j] > v);
        
        if (i < j) {
            swap(nums[i], nums[j]);
        }
    }
    
    return j;
}

void quick_sort(vector<int> &nums, int left, int right)
{
    if (left >= right) {
        return;
    }
    
    int p = partition(nums, left, right);
    quick_sort(nums, left, p);
    quick_sort(nums, p+1, right);
}

int main()
{
    int n;
    cin >> n;
    
    if (n == 0) {
        return 0;
    }
    
    vector<int> nums(n);
    for (int i = 0; i < n; i++) {
        cin >> nums[i];
    }
    
    quick_sort(nums, 0, nums.size()-1);
    
    for (auto n: nums) {
        cout << n << " ";
    }
    
    return 0;
}
```

