FROM ubuntu:18.04

# 设置时区
RUN echo "Asia/Shanghai" > /etc/timezone && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

# 设置中文
ENV LANG C.UTF-8

# 更新源
RUN sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list && \
    apt-get clean

# 安装项目依赖包
RUN apt-get update && \
    apt-get upgrade

RUN apt-get install python3.6 -y && \
    apt-get install python3-pip -y && \
    apt-get install libcurl4 -y && \
    apt-get install libcurl4-openssl-dev -y && \
    apt-get install python3 python-dev python3-dev -y && \
    apt-get install openssl -y && \
    apt-get install libssl-dev -y && \
    apt-get install tzdata -y && \
    rm /etc/localtime

RUN ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

# 设置项目包名称
WORKDIR /Spider-Demo

# 安装python第三方库
COPY requirementd.txt .
RUN pip3 install -r requirementd.txt -i http://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com

COPY . .

ENTRYPOINT ["python3.6", "spider.py"]