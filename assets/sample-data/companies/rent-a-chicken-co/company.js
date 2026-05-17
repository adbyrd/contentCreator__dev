const updatePayload = {
  _id:                  existing._id,
  _owner:               existing._owner,
  owner:                existing.owner,   // SC-07 transition field


  // ─ User-editable fields (sourced from modal form) ─
  title:                projectData.title,
  description:          projectData.description,
  companyName:          projectData.companyName,
  companyDescription:   projectData.companyDescription,
  primaryCategory:      projectData.primaryCategory,
  customerType:         projectData.customerType,
  goal:                 projectData.goal,
  offer:                projectData.offer,
  targetAudience:       projectData.targetAudience ?? projectData.target_audience,
  misconception:        projectData.misconception,


  // ─ Storyboard system fields: PRESERVED from existing record ─
  storyboardStatus:     existing.storyboardStatus     ?? null,
  storyboardStartedAt:  existing.storyboardStartedAt  ?? null,
  storyboardFrameCount: existing.storyboardFrameCount ?? null,
  completedAt:          existing.completedAt          ?? null,
  cancelledAt:          existing.cancelledAt          ?? null,
  firstFrameImage:      existing.firstFrameImage      ?? null,
};
