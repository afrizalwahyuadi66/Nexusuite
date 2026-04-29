# ==============================================================================
# Batch Execution (Rolling Queue / Worker Pool)
# ==============================================================================
echo ""
gum style --foreground 212 --border rounded --border-foreground 99 --padding "0 2" "🚀 Initiating Batch Execution" "Mode: $CONCURRENCY concurrent domains max"
echo ""

mapfile -t targets < "$TARGETS_FILE"
total=${#targets[@]}

BATCH_SUMMARY="$OUTPUT_BASE/batch_summary.txt"
{
    echo "EXECUTION SUMMARY - $(date)"
    echo "=============================="
} > "$BATCH_SUMMARY"

for ((i=0; i<total; i++)); do
    target="${targets[$i]}"
    # Virtual batch assignment for folder grouping
    BATCH_NUM=$((i/CONCURRENCY + 1))
    export BATCH_ID="$BATCH_NUM"

    if grep -qxF "$target" "$SKIP_DOMAIN_FILE" 2>/dev/null; then
        log_msg "!" "\033[1;33m" "$target" "INIT" "Skipped previously."
        continue
    fi

    log_msg "+" "\033[1;34m" "$target" "INIT" "Assigned to Batch $BATCH_NUM"
    echo "  - $target (Batch $BATCH_NUM)" >> "$BATCH_SUMMARY"

    process_target "$target" &

    # Rolling Queue: wait if active background jobs reach CONCURRENCY limit
    while [[ $(jobs -r -p | wc -l) -ge $CONCURRENCY ]]; do
        if ! wait -n 2>/dev/null; then
            :
        fi
    done
done

# Wait for remaining background processes
echo ""
gum style --foreground 204 --border normal --border-foreground 240 --padding "0 2" "⏳ All targets dispatched. Waiting for background tasks to complete..."
while [[ $(jobs -p | wc -l) -gt 0 ]]; do
    if ! wait -n 2>/dev/null; then
        :
    fi
done
echo ""
gum style --foreground 46 --border double --border-foreground 46 --align center --padding "1 4" "✨ PHASE COMPLETE ✨" "All concurrent executions finished successfully."

unset BATCH_ID
