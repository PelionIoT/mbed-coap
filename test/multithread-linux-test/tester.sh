#!/bin/bash

initial_values=(20.0 21.0 22.0 23.0 24.0 25.0 26.0 27.0 28.0 25.9 )
new_values=(30.0 31.0 32.0 33.0 34.0 35.0 36.0 37.0 38.0 35.9 )

function read_default_values {
    echo "Read default values"
    for i in {0..9}
    do
        value=`curl -s -H "Authorization: Basic YWRtaW46c2VjcmV0" "http://127.0.0.1:8080/endpoints/THREAD_${i}/3303/0/temp?sync=true"`
        echo "Thread${i} $value"
        if [ "${initial_values[$i]}" != "$value" ];
        then
            echo "Value ${initial_values[$i]} does not match to $value"
            exit 1
        fi
    done
}

function read_new_values {
    echo "Read new values"
    for i in {0..9}
    do
        value=`curl -s -H "Authorization: Basic YWRtaW46c2VjcmV0" "http://127.0.0.1:8080/endpoints/THREAD_${i}/3303/0/temp?sync=true"`
        echo "Thread${i} $value"
        if [ "${new_values[$i]}" != "$value" ];
        then
            echo "Value ${new_values[$i]} does not match to $value"
            exit 1
        fi
    done
}

function post_new_values {
    echo "Post new values"
    for i in {0..9}
    do
        curl -X PUT -H "Authorization: Basic YWRtaW46c2VjcmV0" "http://127.0.0.1:8080/endpoints/THREAD_${i}/3303/0/temp?sync=true" -d "${new_values[$i]}"
    done
}

function post_default_values {
    echo "Post default values"
    for i in {0..9}
    do
        curl -X PUT -H "Authorization: Basic YWRtaW46c2VjcmV0" "http://127.0.0.1:8080/endpoints/THREAD_${i}/3303/0/temp?sync=true" -d "${initial_values[$i]}"
    done
}
post_default_values
while [ true ]; do
    read_default_values
    sleep 2
    post_new_values
    sleep 2
    read_new_values
    sleep 2
    post_default_values    
    sleep 2
done




