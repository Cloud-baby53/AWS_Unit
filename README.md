# AWS_Unit commits 1 from Kohei

```bash
mkdir AWS_Unit && cd AWS_Unit
echo "# AWS_Unit" >> README.md
git init
git add README.md
git commit -m "first commit"
git remote add origin https://github.com/Cloud-baby53/AWS_Unit.git
git push -u origin master

git branch dev
git checkout dev
```

// 好きに作業する

# AWS_Unit commits 1 to dev brach from Kohei
```bash
git add README.md
git commit -m "first commit"
git push -u origin dev
```

branchを作った時のコミットが更新されているものをmasterにmergeしたときに警告されることを確認する
