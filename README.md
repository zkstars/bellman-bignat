测试：
```
cargo run --color=always --package bellman-bignat --example rollup_bench merkle 1 4
```

执行 example 的 rollup_bench 测试， 有四个账户，发起了一笔转账。 证明构造时间较长，耐心等待。
执行会产生对应的合约和证明文件。
使用remix部署verify.sol, 修改 demo.ts 脚本合约地址 和proof.json。 执行完成链上验证。
(不涉及链上状态变更，所以不需要私钥)