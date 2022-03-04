# 786. 第k个数

- [  题目](https://www.acwing.com/problem/content/description/788/)
- [  提交记录](https://www.acwing.com/problem/content/submission/788/)
- [  讨论](https://www.acwing.com/problem/content/discussion/index/788/1/)
- [  题解](https://www.acwing.com/problem/content/solution/788/1/)
- [  视频讲解](https://www.acwing.com/problem/content/video/788/)



给定一个长度为n的整数数列，以及一个整数k，请用快速选择算法求出数列从小到大排序后的第k个数。

#### 输入格式

第一行包含两个整数 n 和 k。

第二行包含 n 个整数（所有整数均在1~109109范围内），表示整数数列。

#### 输出格式

输出一个整数，表示数列的第k小数。

#### 数据范围

1≤n≤1000001≤n≤100000,
1≤k≤n1≤k≤n

#### 输入样例：

```
5 3
2 4 1 5 3
```

#### 输出样例：

```
3
```





```c++
#include <iostream>
#include <vector>
using namespace std;


int partition(vector<int>& input, int l, int r) {
    auto x = input[r];
    int i = l;
    for (int j = l; j < r; j++) {
        if (input[j] <= x) {
            swap(input[i], input[j]);
            i++;
        }
    }
    swap(input[i], input[r]);
    return i;
}

void solve(vector<int>& input, int k) {
    int l = 0, r = input.size()-1;
    while (l < r) {
        auto p = partition(input, l, r);
        if (p == k) {
            return;
        }
        else if (p > k) {
            r = p - 1;
        }
        else {
            l = p + 1;
        }
    }
}

int main()
{
    int n, k;
    cin >> n >> k;
    
    vector<int> input(n);
    for (int i = 0; i < n; i++) {
        cin >> input[i];
    }
    
    solve(input, k-1);
    cout << input[k-1] << endl;
    
    return 0;
}
```



```c++
#include <iostream>
using namespace std;

const int N = 100010;
int n, k;
int nums[N];

int partition(int *nums, int l, int r)
{
    int i = l-1, j = r+1, x = nums[(l+r) >> 1];
    while (i < j) {
        while (nums[++i] < x);
        while (nums[--j] > x);
        if (i < j ) {
            swap(nums[i], nums[j]);
        }
    }
    return j;
}

int solve(int *nums, int l, int r, int k)
{
    if (l >= r) {
        return nums[l];
    }
    
    int p = partition(nums, l, r);
    if (k <= p) {
        return solve(nums, l, p, k);
    }
    return solve(nums, p+1, r, k);
}

int main()
{
    scanf("%d %d", &n, &k);
    for (int i = 0; i < n; i++) {
        scanf("%d", &nums[i]);
    }
    
    int ans = solve(nums, 0, n-1, k-1);
    printf("%d\n", ans);
    
    return 0;
}
```

