import streamlit as st
from pathlib import Path
def home_page():

	with st.container(height=500, border=False):
		col1, col2, col3 = st.columns([4,4,4])

		with col1:
			st.write("")

		with col2:
			st.image('logo.png', width=400, caption="By The Creators Of Mobexler")

		with col3:
			st.write("")
		

	# Overview Section
	st.markdown(Path("home.md").read_text(),unsafe_allow_html=True)

	


