-- Import outputs/cleaned_flows.csv as cleaned_flows to run these queries.
SELECT attack_cat, COUNT(*) AS attack_flows
FROM cleaned_flows WHERE is_attack = 1
GROUP BY attack_cat ORDER BY attack_flows DESC;

SELECT proto, COUNT(*) AS total_flows,
       SUM(is_attack) AS attack_labelled_flows,
       ROUND(100.0 * SUM(is_attack) / COUNT(*), 2) AS attack_share_pct
FROM cleaned_flows GROUP BY proto ORDER BY total_flows DESC;

SELECT service, ROUND(AVG(total_bytes), 2) AS avg_flow_bytes,
       COUNT(*) AS flows
FROM cleaned_flows GROUP BY service ORDER BY flows DESC;
