package com.example.demo.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2,"Maria Jones"),
            new Student(3,"Anna Smith")
    );

    // FIXED : BUG... GET from STUDENT role still allowed ( but antMatchers(.hasAnyRole()) will correctly block)
    // SOLUTION:  rebuilt @PreAuthorize?
    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")  // replacement for antMatchers(.hasAnyRole())
    public List<Student> getAllSTUDENTS() {
        System.out.println("getAllSTUDENTS");
        return STUDENTS;
    }

    // SPEL syntax from https://www.studytonight.com/spring-framework/spring-expression-language
    // EXAMPLE: @Value("#{'user.name'.toUpperCase()}")

    @PostMapping
    //  How to specify authority as a permission? such as: @PreAuthorize("hasAuthority('${STUDENT_WRITE.getPermission()}')")
    @PreAuthorize("hasAuthority('student:write')")
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println("Placeholder for registering new student = " + student);
    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable("studentId") Integer studentId) {
        System.out.println("Placeholder for deleting student ID = " + studentId);
    }

    @PutMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
        System.out.println(String.format("Placeholder for updating student ID %s, student %s", studentId, student));
    }

}