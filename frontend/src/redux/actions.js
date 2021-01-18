let logMessageCounter = 0;

export const set_field = 'set_field';

export const change_input = 'change_input';

export const log_task_started = 'log_task_started';
export const log_task_done = 'log_task_done';

export const log_task_success = 'log_task_success';
export const log_task_errored = 'log_task_errored';
export const log_task_close = 'log_task_close';

export const setField = (key, value) => {
    return ({
        type: set_field,
        payload: {
            key: key,
            value: value,
        },
    })
};

export const logTaskStarted = (payload) => ({ type: log_task_started, payload });
export const logTaskDone = (payload) => ({ type: log_task_done, payload });

export const logTaskSuccess = (text, timeout = 3000) => ({ type: log_task_success, payload: {text, timeout, timestamp: Date.now() + ++logMessageCounter} });
export const logTaskErrored = (text) => ({ type: log_task_errored, payload: {text, timestamp: Date.now() + ++logMessageCounter} });
export const logTaskClose = (key) => ({ type: log_task_close, payload: key });