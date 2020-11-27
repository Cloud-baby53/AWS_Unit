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
git commit -m "first commit of dev branch"
git push -u origin dev
```

`git branch -a`コマンドでRemote Repositoryに作成されたブランチ("remotes/origin/dev")を確認することができる

Webサイトからdev branchをmasterにmergeするために、pull requestを出します。
そして、Merge pull requestをすることで、dev branchをmaster branchにmergeすることができます。


ここで生まれた疑問
- つながりのないbranchをmaster branch にpull request + mergeすることはできるの？
- また、できない場合どうすればいいの？

検証のために、別のユーザから、Remote Repositoryのmaster branch を更新する

# AWS_Unit commits 2 from Test

```bash
git fetch origin master
git merge remotes/origin/master
git add .
git commit -m "second commit of master from test"
git push -u origin master
```

# AWS_Unit commits 2 to dev brach from Kohei
```bash
git add README.md
git commit -m "second commit of dev branch"
git push -u origin dev
```

このpushしたブランチは、first commitのコミットからsecond commit of dev branchのコミットを作成したため、正常にmergeされた
しかし、WebサイトでRemote Repositoryのdevブランチをmasterブランチに対してpull requestを出すと下記のエラーが発生する
> This branch has conflicts that must be resolved

masterにpull requestを出すときだけ以下の作業を実行してください。
こうなるとめんどくさいので、Close pull requestとdelete branch を実行して、なかったことにします。
解決策としては、Remote Repositoryのmaster branch をLocal Repositoryのmaster branch に適応して
Local Repositoryのmaster branch をdev branchにmergeして修正後に、Remote Repositoryのdev brachにpushする

```bash
git checkout master
git pull origin master
git checkout dev
git merge master
// 競合を修正する
git add .
git commit -m "second commit of dev branch"
git push -u origin dev
```
branchを作った時のコミットが更新されているものをmasterにmergeしたときに警告されることを確認する
