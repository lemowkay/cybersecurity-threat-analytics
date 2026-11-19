import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from pipeline import generate_demo,clean_flows,attack_mix,protocol_risk
import pandas as pd


def test_demo_and_counts():
    flows,check=clean_flows(generate_demo(600,seed=3))
    assert len(flows)==600
    assert 0 <= flows.is_attack.mean() <= 1
    assert attack_mix(flows)['flows'].sum()==flows['is_attack'].sum()
    assert protocol_risk(flows)['total_flows'].sum()==600
    assert check.loc[0,'raw_flows']==600


def test_invalid_labels_excluded_and_normalised():
    d=generate_demo(50,seed=4)
    d.loc[0,'label']=5
    d.loc[1,'label']=0
    d.loc[1,'attack_cat']='Exploits'
    cleaned,audit=clean_flows(d)
    assert len(cleaned)==49
    assert audit.loc[0,'invalid_labels_removed']==1
    assert cleaned.loc[1,'attack_cat']=='Normal'
