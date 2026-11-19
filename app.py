"""Streamlit dashboard for labelled network flow analysis; no IDS deployment."""
import pandas as pd
import plotly.express as px
import streamlit as st
from pipeline import generate_demo, clean_flows, attack_mix, protocol_risk

st.set_page_config(page_title='Cyber Threat Intelligence',page_icon='🛡️',layout='wide')
st.title('Cybersecurity Threat Analytics')
st.caption('UNSW-NB15 • labelled network flows • attack class and protocol patterns')
upload=st.sidebar.file_uploader('Upload official training/testing CSV',type='csv')
if upload:
    raw=pd.read_csv(upload,low_memory=False)
else:
    raw=generate_demo()
    st.warning('SYNTHETIC DEMO: traffic and attack labels are simulated. Upload the original UNSW-NB15 CSV for dataset-derived results.')
try: flows,quality=clean_flows(raw)
except ValueError as e:st.error(str(e));st.stop()
protocols=st.sidebar.multiselect('Protocol',sorted(flows['proto'].unique()),default=sorted(flows['proto'].unique()))
services=st.sidebar.multiselect('Service',sorted(flows['service'].unique()),default=sorted(flows['service'].unique()))
flows=flows[flows['proto'].isin(protocols)&flows['service'].isin(services)]
if flows.empty:st.warning('No flows for current filters');st.stop()
a,b,c=st.columns(3)
a.metric('Analysed flows',f'{len(flows):,}')
b.metric('Attack-labelled flows',f"{flows['is_attack'].sum():,}")
c.metric('Attack-labelled share',f"{flows['is_attack'].mean()*100:.1f}%")
left,right=st.columns(2)
with left:
    mix=attack_mix(flows)
    st.plotly_chart(px.bar(mix,x='flows',y='attack_cat',orientation='h',title='Attack class distribution'),use_container_width=True)
with right:
    by=protocol_risk(flows)
    st.plotly_chart(px.bar(by,x='proto',y='attack_share_pct',range_y=[0,100],title='Within-dataset labelled attack share by protocol'),use_container_width=True)
st.plotly_chart(px.box(flows.dropna(subset=['rate']),x='is_attack',y='rate',log_y=True,title='Flow rate distribution by recorded label',labels={'is_attack':'0 = Normal, 1 = Attack'}),use_container_width=True)
with st.expander('Data audit and interpretation'):
    st.dataframe(quality,use_container_width=True)
    st.write('The dataset is a controlled cyber-range benchmark, not live SOC logs. Flow counts are not incident counts, and attack-labelled share is not the real-world probability of attack. No timestamps are present in the standard train/test splits, so no time-based attack trend is claimed.')
