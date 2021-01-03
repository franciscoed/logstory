import streamlit as st
import plotly.express as px
import re
import pandas as pd
from user_agents import parse


def main():
    # Lb type picker
    lb_type = st.sidebar.radio(
        "LB Type",
        (
            "AWS Classic",
            "AWS Application",
        ),
    )

    st.markdown(
        "<h1 style='text-align: center;'>AWS LB Log Story</h1>", unsafe_allow_html=True
    )
    uploaded_file = st.file_uploader("Upload here you AWS LB Log.")

    # if it has a file it will call the parse function and show the chart
    if uploaded_file is not None:
        if lb_type == "AWS Classic":
            df = parse_clb_log_file(uploaded_file.read().decode("utf-8"))
        else:
            df = parse_alb_log_file(uploaded_file.read().decode("utf-8"))

        # it it's an empty file or not compatible it whould thrown an error
        if df.empty:
            st.error("Invalid Format or empty file")
        # otherwise it will show the charts
        else:
            # Transformations
            # creating a new column with the user agent definition (refer to function below)
            df["ua"] = df.apply(user_agent_definition, axis=1)
            # this column will get just the browser from the user agent field
            df["browser"] = df.apply(
                lambda x: parse(x.user_agent).browser.family, axis=1
            )
            # this column will get just the device from the user agent field
            df["device"] = df.apply(lambda x: parse(x.user_agent).device.family, axis=1)
            # this column will get just the os from the user agent field
            df["os"] = df.apply(lambda x: parse(x.user_agent).os.family, axis=1)

            # Plot bots vs Devices
            # TODO: pull the slice wich contains the bots
            st.header(f"Bot vs Devices")
            fig_ua = px.pie(
                df, names="ua", color_discrete_sequence=px.colors.sequential.RdBu
            )
            st.plotly_chart(fig_ua, use_container_width=True)

            # Plot Browsers
            st.header(f"Browser")
            fig_browser = px.pie(
                df,
                names="browser",
                color_discrete_sequence=px.colors.sequential.RdBu,
            )
            st.plotly_chart(fig_browser, use_container_width=True)

            # Plot Devices
            st.header(f"Devices")
            fig_device = px.pie(
                df,
                names="device",
                color_discrete_sequence=px.colors.sequential.RdBu,
            )
            st.plotly_chart(fig_device, use_container_width=True)

            # Plot OS
            st.header(f"OS")
            fig_os = px.pie(
                df, names="os", color_discrete_sequence=px.colors.sequential.RdBu
            )
            st.plotly_chart(fig_os, use_container_width=True)

            # AWS CLB and ALB have different fiedls for backend code, so I'm adding this if to not have any error
            if lb_type == "AWS Classic":
                # Backend Response
                st.header(f"Backend Response Codes")
                fig_brc = px.pie(
                    df,
                    names="backend_response_code",
                    color_discrete_sequence=px.colors.sequential.RdBu,
                )
                st.plotly_chart(fig_brc, use_container_width=True)

                # LB Response Code
                st.header(f"LB Response Codes")
                fig_erc = px.pie(
                    df,
                    names="elb_response_code",
                    color_discrete_sequence=px.colors.sequential.RdBu,
                )
                st.plotly_chart(fig_erc, use_container_width=True)


# Got this idea from: https://stackoverflow.com/questions/21702342/creating-a-new-column-based-on-if-elif-else-condition
# the idea is to return which kind of device is in use (no matter the OS, brand and etc) and also if it is a bot
def user_agent_definition(row):
    if parse(row["user_agent"]).is_bot:
        val = "bot"
    elif parse(row["user_agent"]).is_mobile:
        val = "mobile"
    elif parse(row["user_agent"]).is_pc:
        val = "pc"
    elif parse(row["user_agent"]).is_tablet:
        val = "tablet"
    else:
        val = "Unknown"
    return val


# map the fields and run a regex, this regex is available on AWS docs
# https://docs.aws.amazon.com/athena/latest/ug/elasticloadbalancer-classic-logs.html
# In the end it builds a Pandas Dataframe and return it
def parse_clb_log_file(uploaded_file):
    fields = [
        "timestamp",
        "elb_name",
        "request_ip",
        "request_port",
        "backend_ip",
        "backend_port",
        "request_processing_time",
        "backend_processing_time",
        "client_response_time",
        "elb_response_code",
        "backend_response_code",
        "received_bytes",
        "sent_bytes",
        "request_verb",
        "url",
        "protocol",
        "user_agent",
        "ssl_cipher",
        "ssl_protocol",
    ]
    regex = r"([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) \"([^ ]*) ([^ ]*) (- |[^ ]*)\" (\"[^\"]*\") ([A-Z0-9-]+) ([A-Za-z0-9.-]*)"
    df = pd.DataFrame(re.findall(regex, uploaded_file), columns=fields)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    # df.set_index("timestamp", inplace=True)
    return df


# map the fields and run a regex, this regex is available on AWS docs
# https://docs.aws.amazon.com/athena/latest/ug/application-load-balancer-logs.html
# In the end it builds a Pandas Dataframe and return it
def parse_alb_log_file(uploaded_file):
    fields = [
        "type",
        "timestamp",
        "alb",
        "client_ip",
        "client_port",
        "backend_ip",
        "backend_port",
        "request_processing_time",
        "backend_processing_time",
        "response_processing_time",
        "alb_status_code",
        "backend_status_code",
        "received_bytes",
        "sent_bytes",
        "request_verb",
        "request_url",
        "request_proto",
        "user_agent",
        "ssl_cipher",
        "ssl_protocol",
        "target_group_arn",
        "trace_id",
        "domain_name",
        "chosen_cert_arn",
        "matched_rule_priority",
        "request_creation_time",
        "actions_executed",
        "redirect_url",
        "lambda_error_reason",
        "target_port_list",
        "target_status_code_list",
        "classification",
        "classification_reason",
    ]
    # https://gist.github.com/jweyrich/8d53a7bf5bad7b5958423cb4e538ab20
    regex = r"([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) \"([^ ]*) ([^ ]*) (- |[^ ]*)\" \"([^\"]*)\" ([A-Z0-9-]+) ([A-Za-z0-9.-]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\" ([-.0-9]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^ ]*)\" \"([^\s]+?)\" \"([^\s]+)\" \"([^ ]*)\" \"([^ ]*)\""
    df = pd.DataFrame(re.findall(regex, uploaded_file), columns=fields)
    # my logs had a \n so I'm removing them
    df = df.replace("\n", "", regex=True)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    # df.set_index("timestamp", inplace=True)
    return df


if __name__ == "__main__":
    main()
