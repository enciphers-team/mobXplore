import streamlit as st
from pathlib import Path
def home_page():

	# st.markdown(
 #    f"""
 #    <h1 style='text-align: center;'>MobXplore </h1>
 #    <h4 style='text-align: center;'>Juice Up Your iOS Security</h4>
 #    """,
 #    unsafe_allow_html=True
	# )
	with st.container(height=500, border=False):
		col1, col2, col3 = st.columns([4,4,4])

		with col1:
			st.write("")

		with col2:
			st.image('mobxplore.png', width=400)

		with col3:
			st.write("")
		

	# Overview Section
	st.markdown(Path("readme.md").read_text(),unsafe_allow_html=True)

	


