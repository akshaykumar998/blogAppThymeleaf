package com.blog.services;

import com.blog.dto.CommentDto;

public interface CommentService {
    void createComment(String postUrl, CommentDto commentDto);
}
