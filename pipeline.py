"""Cyber threat analytics for UNSW-NB15 network flows; offline synthetic demo."""
from __future__ import annotations
import argparse
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT=Path(__file__).resolve().parent
BASE_COLS={'proto','service','state','dur','sbytes','dbytes','rate','attack_cat','label'}
ATTACK_CATS=['Exploits','Fuzzers','DoS','Reconnaissance','Generic','Analysis','Backdoor','Shellcode','Worms']


def generate_demo(n: int=12000, seed: int=17) -> pd.DataFrame:
    """Simulated flows, not actual UNSW-NB15 traffic. For software demonstration only."""
    rng=np.random.default_rng(seed)
    label=rng.choice([0,1],p=[.62,.38],size=n)
    attacks=np.array(['Normal']*n,dtype=object)
    attacks[label==1]=rng.choice(ATTACK_CATS,size=(label==1).sum(),p=[.23,.16,.16,.13,.13,.08,.06,.04,.01])
    proto=rng.choice(['tcp','udp','icmp'],size=n,p=[.70,.25,.05])
    service=rng.choice(['http','dns','ssh','ftp','smtp','-'],size=n,p=[.32,.22,.09,.07,.06,.24])
    state=rng.choice(['FIN','CON','INT','REQ'],size=n,p=[.47,.34,.15,.04])
    durations=rng.exponential(scale=.5,size=n)*(1+label*1.8)
    src_bytes=rng.lognormal(mean=6+label*.3,sigma=1,size=n)
    dst_bytes=rng.lognormal(mean=6-label*.25,sigma=1,size=n)
    rate=rng.lognormal(mean=3+label*.9,sigma=1,size=n)
    return pd.DataFrame({'id':np.arange(1,n+1),'proto':proto,'service':service,'state':state,
        'dur':np.round(durations,4),'sbytes':src_bytes.astype(int),'dbytes':dst_bytes.astype(int),
        'rate':np.round(rate,2),'attack_cat':attacks,'label':label})


def clean_flows(df: pd.DataFrame) -> tuple[pd.DataFrame,pd.DataFrame]:
    missing=BASE_COLS.difference(df.columns)
    if missing: raise ValueError(f'UNSW-NB15 schema missing: {sorted(missing)}')
    d=df.copy()
    for c in ['dur','sbytes','dbytes','rate','label']:
        d[c]=pd.to_numeric(d[c],errors='coerce')
    for c in ['proto','service','state','attack_cat']:
        d[c]=d[c].fillna('Unknown').astype(str).str.strip()
    # Do not drop duplicate flow rows: legitimate identical flows may exist.
    original=len(d)
    d=d[d['label'].isin([0,1])].copy()
    for c in ['dur','sbytes','dbytes','rate']:
        d.loc[d[c]<0,c]=np.nan
    d['attack_cat']=d['attack_cat'].replace({'':'Unknown','nan':'Unknown','-':'Unknown'})
    d.loc[d['label']==0,'attack_cat']='Normal'
    d.loc[(d['label']==1)&d['attack_cat'].eq('Normal'),'attack_cat']='Unknown attack'
    d['total_bytes']=d[['sbytes','dbytes']].sum(axis=1,min_count=1)
    d['is_attack']=d['label'].astype(int)
    quality=pd.DataFrame([{'raw_flows':original,'valid_binary_label_flows':len(d),
                           'invalid_labels_removed':original-len(d),
                           'missing_rates':int(d['rate'].isna().sum()),
                           'missing_traffic_bytes':int(d['total_bytes'].isna().sum()),
                           'unique_attack_categories':int(d.loc[d['is_attack']==1,'attack_cat'].nunique())}])
    return d,quality


def attack_mix(flows: pd.DataFrame) -> pd.DataFrame:
    bad=flows[flows['is_attack']==1]
    mix=bad.groupby('attack_cat',as_index=False).agg(flows=('is_attack','size'),bytes=('total_bytes','sum'))
    if len(mix): mix['share_of_attack_flows_pct']=100*mix['flows']/len(bad)
    else: mix['share_of_attack_flows_pct']=pd.Series(dtype=float)
    return mix.sort_values('flows',ascending=False)


def protocol_risk(flows: pd.DataFrame) -> pd.DataFrame:
    by=flows.groupby('proto',as_index=False).agg(total_flows=('is_attack','size'),
                                                 attack_flows=('is_attack','sum'),
                                                 total_bytes=('total_bytes','sum'))
    by['attack_share_pct']=by['attack_flows']/by['total_flows']*100
    # Descriptive share in this labelled dataset, NOT an estimated real-world probability.
    return by.sort_values('total_flows',ascending=False)


def make_outputs(raw: pd.DataFrame,out: Path,reports:Path,mode:str) -> dict:
    out.mkdir(parents=True,exist_ok=True); reports.mkdir(parents=True,exist_ok=True)
    flows,audit=clean_flows(raw)
    if flows.empty: raise ValueError('No valid rows after cleaning')
    mix=attack_mix(flows); byproto=protocol_risk(flows)
    byservice=flows.groupby('service',as_index=False).agg(flows=('is_attack','size'),
                                                          attack_flows=('is_attack','sum'))
    byservice['attack_share_pct']=100*byservice['attack_flows']/byservice['flows']
    byservice=byservice.sort_values('flows',ascending=False)
    bystate=flows.groupby('state',as_index=False).agg(flows=('is_attack','size'),attack_flows=('is_attack','sum'))
    summary=flows.groupby('is_attack',as_index=False).agg(median_duration=('dur','median'),
             p95_rate=('rate',lambda x:x.quantile(.95)),median_bytes=('total_bytes','median'))
    kpis={'data_mode':mode,'total_network_flows':len(flows),'attack_labeled_flows':int(flows['is_attack'].sum()),
          'attack_flow_share_pct':round(100*float(flows['is_attack'].mean()),2),
          'distinct_attack_types':int(mix['attack_cat'].nunique())}
    for name,d in [('cleaned_flows',flows),('attack_categories',mix),('protocol_risk',byproto),
                   ('service_risk',byservice),('states',bystate),('traffic_profile',summary),
                   ('data_quality',audit),('kpis',pd.DataFrame([kpis]))]:
        d.to_csv(out/f'{name}.csv',index=False)
    plt.rcParams.update({'axes.spines.top':False,'axes.spines.right':False,'font.size':10})
    fig,ax=plt.subplots(figsize=(10,5))
    if len(mix):
        m=mix.sort_values('flows').tail(9)
        ax.barh(m['attack_cat'],m['flows'],color='#C25A48')
    ax.set_title('Distribution of attack-labelled network flows',loc='left',fontweight='bold')
    ax.set_xlabel('Flow count (not incidents)')
    fig.tight_layout();fig.savefig(reports/'attack_mix.png',dpi=170);plt.close(fig)
    fig,ax=plt.subplots(figsize=(9,4))
    ax.bar(byproto['proto'],byproto['attack_share_pct'],color='#B97A38')
    ax.set_ylim(0,100);ax.set_ylabel('Attack-labelled flows (%)')
    ax.set_title('Attack-labelled share by protocol — sampled dataset',loc='left',fontweight='bold')
    fig.tight_layout();fig.savefig(reports/'protocol_exposure.png',dpi=170);plt.close(fig)
    print('Cybersecurity:',kpis)
    return kpis


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,help='Official UNSW_NB15_training-set.csv or testing-set.csv')
    parser.add_argument('--demo',action='store_true',help='Generate fictional flows instead')
    args=parser.parse_args()
    if args.input and args.demo:parser.error('Choose --input or --demo')
    if args.input:
        raw=pd.read_csv(args.input,low_memory=False);mode='REAL: user-supplied UNSW-NB15 file'
    else:
        raw=generate_demo();mode='SYNTHETIC DEMO — NOT REAL NETWORK TRAFFIC'
        raw.to_csv(ROOT/'data'/'demo_flows.csv',index=False)
    make_outputs(raw,ROOT/'outputs',ROOT/'reports',mode)

if __name__=='__main__':main()
