class ProjectParticipation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    role = models.ForeignKey(Group, on_delete=models.CASCADE, null=True, blank=True)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Project Participation'
        verbose_name_plural = 'Project Participations'

    def clean(self):
        if self.user is None and self.role is None:
            raise ValidationError('Either user or group must be set')

    def __str__(self):
        if self.user is not None:
            return f"{self.user.username} in {self.project.name}"
        elif self.role is not None:
            return f"{self.role.name} in {self.project.name}"
        else:
            return f"No user or group in {self.project.name}"

