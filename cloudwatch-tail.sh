#!/bin/bash
GAME_ID=japan
TEAM_ID=team2
SERVERADDRESS=< refund_endpoint >
KEYWORD='Unicorn Refund Request'
UUIDCOLUM=6

while read -r UUID;
do
    response=`curl -sS -H "Accept: application/json" -X POST -d '{"game":"'"$GAME_ID"'", "team":"'"$TEAM_ID"'", "order":"'"$UUID"'"}' $SERVERADDRESS 2>&1`
    echo "[resund_uuid] "$UUID "[result_message] "$response >> refund.log
done < <(awslogs get /horse/app_logs -w -G -S -f $KEYWORD | awk '{print $'$UUIDCOLUM'; fflush()}')


# Install Command
# yum install -y awslogs

# 今回は /horse/app_logsというロググループをリアルタイム監視(-w)をして$KEYWORDに一致するもの(-f)のみ表示。
# ロググループ名とストリーム名は非表示(-G, -S)
# 詳細は```cloudwatch tail```と検索したらたくさん参考資料は出てくので参考にしてください
